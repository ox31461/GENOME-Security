"""
asymmetric_learning_gate.py

Reusable defense primitive against adversarial baseline poisoning
("boiling the frog") in continuous behavioral-biometric authentication.

Core idea
---------
A naive continuously-adapting baseline treats every incoming telemetry
sample (keystroke timing, mouse dynamics, etc.) as a valid training
example and folds it into the baseline via some form of online update
(e.g. an exponential moving average). This is exploitable: an attacker
who has obtained a live, authenticated session (e.g. via token theft or
malware running under the victim's session) can slowly shift their own
behavior profile into the trust envelope by injecting behavior that is
*mostly* consistent with the victim but drifts a little further from
the true baseline each time. Because the system updates on every
sample, the baseline itself walks toward the attacker.

The Asymmetric Learning Gate (ALG) fixes this with two independent
mechanisms:

1. Asymmetric trust: the baseline is NEVER updated from ambient/
   continuous telemetry, no matter how "normal" it looks. It is only
   ever a *candidate* for update immediately following a high-assurance
   anchor event (e.g. a fresh FIDO2/WebAuthn hardware-backed assertion,
   a platform authenticator unlock, a DPoP-bound token refresh backed by
   possession of the private key). Continuous telemetry is used only to
   compute a trust/risk score against the CURRENT frozen baseline -- it
   never feeds back into what the baseline considers "normal".

2. Quarantine buffer: even data collected in the window immediately
   after a high-assurance anchor event is not merged into the live
   baseline immediately. It is staged in a quarantine buffer. Only once
   multiple independent anchor-validated batches are statistically
   consistent with each other (low inter-batch variance, no monotonic
   drift trend) does the quarantine content get promoted into the live
   baseline. A single compromised-but-hardware-attested session is not
   enough to move the baseline; the attacker would need to pass
   hardware-backed re-authentication multiple times while producing
   behavior that doesn't look like a drifting attack pattern, which is
   both harder to obtain and statistically detectable (drift-trend
   check below).

This module is deliberately framework-agnostic (plain numpy) so it can
be reused by both the research simulation and later a production risk
engine.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

import numpy as np


@dataclass
class QuarantineBatch:
    """A batch of samples collected after one high-assurance anchor event."""

    mean: float
    std: float
    n: int


@dataclass
class AsymmetricLearningGate:
    """
    Implements the asymmetric-trust + quarantine-buffer baseline defense
    for a single scalar behavioral feature (the simulation uses one
    feature for clarity; in production this generalizes to a feature
    vector / covariance update).

    Parameters
    ----------
    initial_mean, initial_std:
        The enrolled baseline statistics (established at account
        creation time under a trusted/witnessed enrollment ceremony).
    required_anchor_batches:
        Number of consecutive anchor-validated batches that must agree
        with each other before quarantine contents are promoted into
        the live baseline.
    max_batch_z:
        A quarantine batch is rejected outright (not even queued) if its
        mean is more than this many baseline-standard-deviations away
        from the CURRENT live baseline. This bounds how much a single
        anchor event can possibly move things, even post-validation.
    max_drift_trend:
        If the sequence of queued batch means is monotonically moving
        in one direction by more than this fraction of the baseline std
        per batch, we treat it as a slow-drift (poisoning) attack
        pattern and reset the quarantine buffer rather than promoting.
    ema_alpha:
        Smoothing factor used only when merging a validated quarantine
        window into the live baseline (this is NOT the per-sample
        online update that naive systems use -- it only ever fires after
        the gate above passes).
    """

    initial_mean: float
    initial_std: float
    required_anchor_batches: int = 3
    max_batch_z: float = 3.0
    max_drift_trend: float = 0.6
    ema_alpha: float = 0.35

    mean: float = field(init=False)
    std: float = field(init=False)
    _quarantine: list = field(default_factory=list, init=False)
    merges: int = field(default=0, init=False)
    rejected_batches: int = field(default=0, init=False)
    drift_resets: int = field(default=0, init=False)

    def __post_init__(self):
        self.mean = self.initial_mean
        self.std = self.initial_std

    # ------------------------------------------------------------------
    # Continuous telemetry path (read-only w.r.t. the baseline)
    # ------------------------------------------------------------------
    def trust_score(self, sample: float) -> float:
        """
        Return a risk z-score of `sample` against the CURRENT frozen
        baseline. Continuous telemetry only ever calls this; it never
        calls any mutating method on the gate.
        """
        if self.std <= 1e-9:
            return 0.0 if abs(sample - self.mean) < 1e-9 else math.inf
        return abs(sample - self.mean) / self.std

    # ------------------------------------------------------------------
    # High-assurance anchor path (the only path that can ever mutate
    # the baseline, and only through the quarantine gate)
    # ------------------------------------------------------------------
    def submit_anchor_batch(self, samples: np.ndarray) -> str:
        """
        Called with a short window of telemetry collected immediately
        following a verified high-assurance anchor event (hardware-backed
        WebAuthn assertion, etc). Returns a string describing what
        happened: "rejected", "queued", "merged", or "drift_reset".
        """
        samples = np.asarray(samples, dtype=float)
        batch_mean = float(samples.mean())
        batch_std = float(samples.std(ddof=1)) if len(samples) > 1 else self.std

        # Step 1: hard outlier gate against the CURRENT live baseline.
        z = self.trust_score(batch_mean)
        if z > self.max_batch_z:
            self.rejected_batches += 1
            # A single anchor event, however cryptographically strong,
            # can never on its own justify a large baseline jump.
            return "rejected"

        self._quarantine.append(QuarantineBatch(batch_mean, batch_std, len(samples)))

        # Step 2: drift-trend check across queued batches. A poisoning
        # attacker needs many anchor events, and will tend to produce a
        # monotonic walk away from the original baseline. Genuine natural
        # behavior change (e.g. new keyboard, RSI, etc.) is rare and
        # roughly a one-off shift, not a sustained monotonic walk, so we
        # treat a detected monotonic trend as suspicious and reset.
        if len(self._quarantine) >= 2:
            means = np.array([b.mean for b in self._quarantine])
            diffs = np.diff(means)
            if len(diffs) >= 2:
                same_sign = np.all(diffs > 0) or np.all(diffs < 0)
                total_move = abs(means[-1] - means[0])
                if same_sign and self.std > 1e-9 and (total_move / self.std) > (
                    self.max_drift_trend * len(diffs)
                ):
                    self._quarantine.clear()
                    self.drift_resets += 1
                    return "drift_reset"

        # Step 3: promotion check -- need enough independent
        # anchor-validated batches that are mutually consistent.
        if len(self._quarantine) >= self.required_anchor_batches:
            means = np.array([b.mean for b in self._quarantine])
            # Mutual consistency: spread of batch means must be small
            # relative to the existing baseline std (i.e. they agree
            # with each other, not just individually close to baseline).
            spread = float(means.std(ddof=1)) if len(means) > 1 else 0.0
            if self.std <= 1e-9 or spread / max(self.std, 1e-9) < 1.0:
                new_mean = float(means.mean())
                self.mean = (1 - self.ema_alpha) * self.mean + self.ema_alpha * new_mean
                # Baseline std is allowed to adapt slowly too, bounded.
                new_std = float(np.mean([b.std for b in self._quarantine]))
                self.std = (1 - self.ema_alpha) * self.std + self.ema_alpha * new_std
                self._quarantine.clear()
                self.merges += 1
                return "merged"

        return "queued"


@dataclass
class NaiveContinuousBaseline:
    """
    The insecure comparison baseline: updates on every single telemetry
    sample via an exponential moving average, regardless of assurance
    level. This models what many first-generation continuous-auth
    products actually ship, and is exactly what ALG is designed to
    replace.
    """

    initial_mean: float
    initial_std: float
    alpha: float = 0.02  # small per-sample learning rate, typical of EMA baselines

    mean: float = field(init=False)
    std: float = field(init=False)

    def __post_init__(self):
        self.mean = self.initial_mean
        self.std = self.initial_std

    def trust_score(self, sample: float) -> float:
        if self.std <= 1e-9:
            return 0.0 if abs(sample - self.mean) < 1e-9 else math.inf
        return abs(sample - self.mean) / self.std

    def observe(self, sample: float) -> None:
        """Every single telemetry sample updates the baseline. This is
        the vulnerability: there is no distinction between ambient
        telemetry and a high-assurance moment."""
        err = sample - self.mean
        self.mean += self.alpha * err
        self.std = (1 - self.alpha) * self.std + self.alpha * abs(err)
