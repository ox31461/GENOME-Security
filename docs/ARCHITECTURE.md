# Architecture

## Vision

GENOME Security is a continuous, adaptive behavioral-biometric
authentication system. "Continuous" means authentication is not a
single point-in-time event (login) but an ongoing trust assessment
throughout a session, informed by how a user types, moves the mouse,
and interacts with their device. "Adaptive" means the system's model
of "normal" behavior for a given user can evolve over time (people's
behavior genuinely drifts — new keyboard, RSI, tiredness) — but, per
our research survey, adaptive baselines are exactly the component that
has been historically vulnerable to slow poisoning attacks, which is
why Phase 1 focuses there.

GENOME Security deliberately does **not** reinvent device-bound
identity, token binding, or post-quantum cryptography — those are
mature, standardized elsewhere (FIDO2/WebAuthn, DPoP RFC 9449, PUFs,
ML-KEM/ML-DSA) and GENOME Security's job is to integrate them
correctly. See `docs/research` cross-reference in `PHASE_PLAN.md` for
what's reused vs. what's novel.

## System layers (full target architecture)

```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 5: Risk Decision / CARTA Policy Engine                     │
│  - Continuous Adaptive Risk & Trust Assessment (Gartner CARTA)   │
│  - Combines all signals below into a session risk score          │
│  - Policy: step-up auth, session restriction, or termination     │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│ Layer 4: Baseline Integrity (NOVEL — Phase 1 scope)              │
│  - Asymmetric Learning Gate: baseline only updates from           │
│    quarantine-validated, high-assurance-anchor-gated batches      │
│  - Defends against adversarial baseline poisoning                │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│ Layer 3: Input Authenticity (NOVEL — Phase 1 scope)              │
│  - Statistical/ML detector: genuine vs. synthetic input timing   │
│  - OS input-path anomaly signals (best-effort, honestly partial) │
│  - Defends against synthetic input injection attacks             │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│ Layer 2: Identity & Session Binding (STANDARDS — Phase 2 scope)  │
│  - FIDO2/WebAuthn device-bound passkeys (phishing-resistant,     │
│    hardware-backed, the only source of "high-assurance anchor    │
│    events" for Layer 4)                                          │
│  - DPoP (RFC 9449) token binding (stolen tokens are unusable      │
│    without the bound private key)                                │
│  - Post-quantum signatures/KEM for the long-term credential       │
│    material (ML-DSA / ML-KEM), defense against "harvest now,     │
│    decrypt later"                                                 │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│ Layer 1: Telemetry Capture (Phase 2 scope — client SDK)          │
│  - Keystroke dynamics (dwell/flight time), mouse dynamics         │
│  - Local-only raw capture; only derived features leave the device│
└─────────────────────────────────────────────────────────────────┘
```

## Phase 1 data flow (what actually exists in this repo today)

Phase 1 ships **research-grade, runnable simulations** of Layers 3 and
4 — the two genuinely novel defenses — as standalone Python modules and
scripts, with real measured results. It does not yet ship Layers 1, 2,
or 5 as production code; those are standards-integration work for
Phase 2 (see `PHASE_PLAN.md`).

```
 Simulated telemetry generator            Simulated attacker
 (genuine human-like timing)              (poisoning / injection)
          │                                       │
          ▼                                       ▼
┌────────────────────┐                 ┌────────────────────────┐
│ synthetic_input_    │                 │ attacker_injected_      │
│ detector.py          │ ◄── feeds ──── │ sample() in              │
│ (Layer 3 prototype)  │                 │ simulate_poisoning_...  │
└────────────────────┘                 └────────────────────────┘
          │                                       │
          ▼                                       ▼
   genuine/synthetic                    continuous telemetry stream
   classification + AUC                           │
                                                   ▼
                                     ┌─────────────────────────────┐
                                     │ AsymmetricLearningGate       │
                                     │ (Layer 4 prototype)          │
                                     │  - trust_score() [read-only] │
                                     │  - submit_anchor_batch()     │
                                     │    [the only mutator]        │
                                     └─────────────────────────────┘
                                                   │
                                                   ▼
                                     measured: attacker acceptance %,
                                     legitimate-user acceptance %
```

## Why these two layers, specifically

Per the completed research survey (NULL-VOID repo,
`docs/research/continuous-biometric-authentication.md`, branch
`research/continuous-biometric-auth`), the rest of the plausible
architecture for continuous adaptive biometric authentication is
already mature and standardized:

- Behavioral biometrics as a general technique: mature in commercial
  products (BioCatch, BehavioSec and similar).
- FIDO2/WebAuthn device-bound passkeys: standardized, widely deployed.
- DPoP token binding: standardized (RFC 9449), growing deployment.
- PUFs for hardware root of trust: mature in secure-element hardware.
- Post-quantum ML-KEM/ML-DSA: standardized by NIST (FIPS 203/204).
- Gartner CARTA as a policy framework: an established industry
  framework, not something to reinvent.

What nobody has shipped a credible, documented defense for yet:
adversarial baseline poisoning of continuously-adapting behavioral
models, and robust detection of increasingly sophisticated synthetic
input injection. That is GENOME Security's actual contribution, and
Phase 1 proves both out with working code and real measured results.
