# Baseline Poisoning Defense — Research Prototype

This folder contains a runnable simulation and reusable defense module
for the **asymmetric learning gate (ALG)**: the mechanism GENOME Security
uses to stop an attacker from slowly poisoning a continuously-adapting
behavioral biometric baseline ("boiling the frog").

## Files

- `asymmetric_learning_gate.py` — the defense itself (`AsymmetricLearningGate`)
  plus a `NaiveContinuousBaseline` comparison class modeling a typical
  first-generation continuous-auth baseline (EMA update on every sample).
- `simulate_poisoning_attack.py` — runs the attack scenario against both
  baseline types and prints a round-by-round comparison.

## How to run

```bash
pip install -r ../requirements.txt
cd research/baseline_poisoning
python simulate_poisoning_attack.py
```

## Attack scenario simulated

- A victim has a stable behavioral feature (modeled here as mean
  inter-keystroke interval, 180ms ± 18ms).
- An attacker gets a live, authenticated session (stolen DPoP-bound
  token used from a malware-controlled process, or hijacked session).
  They **cannot** forge hardware-backed FIDO2/WebAuthn assertions — those
  require physical possession + user presence — so every high-assurance
  "anchor" event in the simulation is still genuinely the victim.
- Between anchor events, the attacker injects their own ambient
  telemetry, starting matched to the victim and ramping, over 30 rounds,
  toward their own natural typing rhythm (260ms ± 22ms).
- We measure, each round, what fraction of the attacker's **own true**
  behavior would be accepted (z-score < 2.0) by (a) a naive EMA
  baseline that updates on every sample, and (b) the ALG-protected
  baseline that only ever updates from quarantined, multiply-validated,
  anchor-only batches.

## Actual results from a real run (seed=42, reproducible)

```
rnd  naive_mu   alg_mu        gate  naive_atk%  alg_atk%  naive_vic%  alg_vic%
  0    180.61   180.00      queued        0.0%      1.5%       78.0%     95.5%
  5    182.16   180.79      merged        0.0%      4.5%       83.0%     97.0%
 10    192.75   179.83      queued        3.5%      3.5%       62.5%     97.5%
 15    200.29   180.70      queued        7.5%      2.5%       70.0%     98.0%
 20    210.45   179.54      merged       22.5%      1.5%       42.0%     93.0%
 25    221.94   179.37      queued       48.0%      0.5%       39.0%     93.0%
 30    233.46   178.01      queued       74.5%      2.5%       33.5%     94.0%
 35    244.80   179.50      merged       97.5%      3.0%       27.0%     93.0%
 39    243.63   180.68      queued       93.5%      3.0%       32.0%     97.5%

=== Summary ===
Victim true mean: 180.0, Attacker true mean: 260.0
Naive baseline drifted from 180.00 -> 243.63 (moved 63.63 of 80.00 possible ms)
ALG baseline drifted from 180.00 -> 180.68 (moved 0.68 of 80.00 possible ms)

Final-5-rounds avg attacker acceptance rate: naive=95.4% vs ALG=2.8%
Final-5-rounds avg legitimate-victim acceptance rate (usability): naive=29.0% vs ALG=95.5%

ALG internal stats: merges=13, rejected_batches=0, drift_resets=0
```

(Full round-by-round output is reproducible by running the script;
the table above is a representative excerpt from the real run.)

## What the results mean

- **The naive baseline is fully poisoned.** By round 39, it has walked
  80% of the way from the victim's true behavior to the attacker's, and
  it now accepts the attacker's real behavior 95.4% of the time. Worse
  for usability: because the baseline has moved so far from the real
  victim, it now *rejects* the legitimate victim 71% of the time
  (29.0% acceptance) — a naive continuously-adapting baseline doesn't
  just let the attacker in, it actively locks out the real user as a
  side effect of the same poisoning.
- **The ALG-protected baseline holds.** Across the same 39 rounds it
  moved only 0.68ms (0.9% of the possible drift), the attacker's real
  acceptance rate stays near noise floor (2.8%, consistent with the 2
  sigma threshold's own false-accept rate on an unrelated distribution),
  and the legitimate victim's usability stays high (95.5%).
- The `drift_resets=0` and `rejected_batches=0` counters show that in
  *this* run the attacker's batches were never individually extreme
  enough to hit the hard per-batch z-gate, and the slow ramp wasn't
  steep enough to trip the monotonic-drift-trend reset either — yet the
  gate still held, because the attacker never controls anchor events in
  the first place. The quarantine-buffer mechanism's real job is the
  second line of defense (catching a drift pattern among anchor
  batches); the first and primary line of defense is that **continuous
  telemetry is structurally excluded from ever training the baseline**,
  regardless of how it looks statistically.

## Honest limitations of this simulation

- This models a **single scalar feature**. A production system uses a
  feature vector across many behavioral dimensions (keystroke dynamics,
  mouse dynamics, app usage patterns); the same asymmetric-trust +
  quarantine principle generalizes, but multivariate drift detection
  (e.g. Mahalanobis distance, subspace drift) is more involved than the
  z-score check modeled here and is Phase 2 work.
- The simulation assumes anchor events are always genuinely the victim
  (hardware-backed WebAuthn assertions cannot be forged remotely). If an
  attacker has **physical possession of the enrolled authenticator**
  (e.g. stolen hardware key + known PIN), this defense does not help —
  that's a different threat captured separately in `THREAT_MODEL.md`
  as physical device theft.
- Parameters (thresholds, batch sizes, EMA alpha) were chosen to be
  reasonable illustrative defaults, not tuned against a real dataset or
  adversarially tested against an adaptive attacker who knows the exact
  gate parameters and optimizes against them. An adaptive attacker aware
  of `max_drift_trend` could in principle pace their drift just under
  the detection threshold over a much longer time horizon — the
  practical mitigation for that (not yet implemented in Phase 1) is
  bounding the *total* lifetime drift a baseline is allowed to
  accumulate without a full re-enrollment ceremony, which is listed as
  Phase 2 hardening work.
