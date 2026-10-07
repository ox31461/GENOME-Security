# GENOME Security

Continuous, adaptive behavioral-biometric authentication — built on
mature standards (FIDO2/WebAuthn device-bound passkeys, DPoP token
binding, post-quantum ML-KEM/ML-DSA, PUF hardware roots of trust,
Gartner's CARTA framework) where they already solve the problem, and
focused novel engineering where they don't.

This project follows a completed research survey (see the sibling
NULL-VOID repo, branch `research/continuous-biometric-auth`, file
`docs/research/continuous-biometric-authentication.md`) that benchmarked
this idea against real industry/academic prior art. Its conclusion:
most of the plausible architecture for continuous adaptive biometric
auth is already mature and standardized elsewhere. GENOME Security's
job is to integrate those pieces correctly — **not** reinvent them —
and to build real, working solutions for the two gaps nobody has
shipped a credible defense for yet:

1. **Adversarial baseline poisoning** ("boiling the frog") — an
   attacker with a live but compromised session slowly nudging a
   continuously-adapting behavioral baseline toward their own behavior.
2. **Synthetic input injection** — malware injecting realistic
   keystroke/mouse events (Bezier-curve paths, Gaussian-noise timing)
   designed to pass a naive trust-score check.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — full system design,
  layers, data flow, and how Phase 1 fits the eventual full stack.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — adversary model
  mapping each threat to its specific defense, stated honestly
  including residual risk.
- [`docs/PHASE_PLAN.md`](docs/PHASE_PLAN.md) — what Phase 1 covers vs.
  what Phase 2 (client SDK, server risk engine, demo app, full
  FIDO2/WebAuthn + DPoP integration) will cover.

## What's in this repo

```
research/
  baseline_poisoning/          # Asymmetric Learning Gate: the defense
                                # against adversarial baseline poisoning
  synthetic_input_detection/   # Statistical detector for synthetic
                                # input injection + honest OS-attestation
                                # feasibility writeup
```

Both are real, runnable Python with real measured results from
actually running the code (not fabricated numbers) — see each folder's
own README for the full output and honest discussion of limitations.

## How to run everything

```bash
pip install -r research/requirements.txt

# Baseline poisoning attack simulation (naive vs. protected baseline)
cd research/baseline_poisoning
python simulate_poisoning_attack.py

# Synthetic input injection detector evaluation
cd ../synthetic_input_detection
python detector.py
```

## Headline results (from real runs — see per-folder READMEs for full output)

**Baseline poisoning defense**: against a 39-round slow-poisoning
attack, a naive continuously-adapting baseline ends up accepting the
attacker's true behavior **95.4%** of the time (and, as a side effect,
locks out the real legitimate user down to **29.0%** acceptance). The
same attack against the Asymmetric Learning Gate leaves attacker
acceptance at **2.8%** and legitimate-user acceptance at **95.5%**.

**Synthetic input injection detector**: cross-validated accuracy of
**88.3%** (AUC 0.958) for keystroke timing and **94.5%** (AUC 0.990)
for mouse timing, distinguishing genuine human-like timing from
Bezier-curve/Gaussian-jitter synthetic injection, using structural
features (1/f spectral slope, kurtosis, physiological tremor band)
rather than mean/variance that an attacker could trivially fake.

## Status

**Phase 1 is complete.** The two novel defenses identified by the
research survey — the Asymmetric Learning Gate against baseline
poisoning, and the structural-feature detector against synthetic input
injection — are built, runnable, and validated with real simulated
measurements documented above and in `research/*/README.md`. The
honest, partially-unsolved problem of cryptographically attesting an
input event's physical hardware origin is documented transparently in
`research/synthetic_input_detection/attested_input_pipeline.md` rather
than papered over.

**Phase 2 (not yet started)** will build the production system around
these defenses: a client SDK (keystroke/mouse telemetry capture,
FIDO2/WebAuthn registration & assertion, DPoP proof-of-possession), a
server risk engine (production Asymmetric Learning Gate and detector,
DPoP validation, CARTA-aligned policy decisions, post-quantum
ML-KEM/ML-DSA credential material), and a demo application with a live
trust-score dashboard. See `docs/PHASE_PLAN.md` for the full breakdown.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE). Chosen for its explicit
patent grant, which is a relevant consideration for a security project
that may develop defensive techniques worth protecting from patent
trolling while remaining fully open source.
