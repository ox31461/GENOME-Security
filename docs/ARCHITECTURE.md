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
│ Layer 2: Identity & Session Binding (STANDARDS — Phase 2: DONE*) │
│  - FIDO2/WebAuthn device-bound passkeys (phishing-resistant,     │
│    hardware-backed, the only source of "high-assurance anchor    │
│    events" for Layer 4)                                          │
│  - DPoP (RFC 9449) token binding (stolen tokens are unusable      │
│    without the bound private key)                                │
│  - Post-quantum signatures/KEM for the long-term credential       │
│    material (ML-DSA / ML-KEM) — NOT implemented in Phase 2,      │
│    deferred; see "Phase 2 divergences" below                     │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│ Layer 1: Telemetry Capture (Phase 2: DONE, web client only)      │
│  - Keystroke dynamics (inter-keydown interval timing), mouse     │
│    dynamics (inter-mousemove interval timing)                    │
│  - Local-only raw capture; only derived interval timings leave   │
│    the device — never key values or cursor positions             │
└─────────────────────────────────────────────────────────────────┘
```

\* "DONE" means implemented and running end-to-end for the web client
(`sdk-web/` + `server/` + `demo-app/`); see "Phase 2 divergences" below
for what was deliberately deferred or simplified relative to the
original sketch above.

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

## Phase 2 data flow (what actually exists in this repo today)

Phase 2 ships Layers 1, 2, and the CARTA-style decision tier of Layer 5
as running production code — a Rust server (`server/`), a TypeScript
browser SDK (`sdk-web/`), and a wired-up demo (`demo-app/`) — built
directly on top of the Phase 1 Python research prototypes (ported, not
reimplemented blind: `server/src/alg.rs` and `server/src/detector.rs`
carry over the same quarantine/anchor thresholds and timing-moment /
spectral features validated in Phase 1).

```
 Browser (sdk-web/ + demo-app/)                 Server (server/, axum)
┌──────────────────────────────┐               ┌───────────────────────────────┐
│ navigator.credentials         │  WebAuthn     │ webauthn-rs: registration /    │
│ .create()/.get()              │ ──ceremony──► │ assertion verification         │
│ (passkey reg / login)         │               │  -> successful assertion =     │
│                                │               │     high-assurance anchor      │
│ WebCrypto ES256 keypair       │               │     event (Layer 4 trigger)    │
│ -> DPoP proof per request      │  DPoP header  │                                 │
│    (htm/htu/iat/jti/jkt/ath)  │ ──on login &─► │ dpop.rs: proof verify, replay   │
│                                │   telemetry   │ window, cnf.jkt session bind    │
│ KeystrokeCapture/MouseCapture │               │                                 │
│ -> interval-timing batches     │  POST         │ detector.rs: synthetic vs.      │
│    (timing only, never key    │ /api/telemetry│ genuine timing classification   │
│    values or positions)       │ ─────────────►│         │                        │
│                                │               │         ▼                       │
│ Live trust dial + decision    │  JSON          │ alg.rs: quarantine buffer /     │
│ badge updated per response    │ ◄─────────────│ anchor-gated baseline merge     │
└──────────────────────────────┘  trust_score,  │         │                        │
                                   decision,     │         ▼                       │
                                   synthetic_p,  │ CARTA-style decision:           │
                                   gate_outcome  │ allow / stepup / deny           │
                                                 └───────────────────────────────┘
```

### Phase 2 divergences from the original sketch

- **Post-quantum credential material (ML-DSA/ML-KEM) was not
  implemented.** `webauthn-rs` negotiates classical COSE algorithms
  (ECDSA/RSA), and DPoP proofs use classical ES256. This is an honest
  gap, not an oversight — PQC migration for WebAuthn/DPoP is still
  maturing industry-wide and was out of scope for a Phase 2 that
  otherwise reuses existing crates rather than hand-rolling crypto.
- **Device-bound / non-syncable credential enforcement is deferred.**
  The server uses `webauthn-rs`'s standard (non-attested) passkey
  registration flow rather than its `attested_passkey` flow, which
  would require curating a trusted manufacturer root-CA
  (`attestation_ca_list`) and would reject common synced/Hybrid
  passkeys (iCloud Keychain, Google Password Manager) most real users
  already have. This is an explicit, documented trade-off (see the
  module doc comment in `server/src/auth.rs`) against the stricter
  "device-bound, non-syncable" framing in the original threat model;
  full enforcement is noted there as follow-on hardening work, not a
  Phase 2 claim.
- **Store is in-memory + SQLite**, explicitly documented in
  `server/src/store.rs` and `server/README.md`-equivalent comments as
  not suitable for a real multi-instance deployment (no replication,
  no backup, no durability guarantees beyond a single SQLite file).
- **Layer 1 (telemetry capture) is web-only.** No native desktop
  client or OS input-path anomaly signal integration
  (`attested_input_pipeline.md`'s Raw Input/evdev/Input-Monitoring
  recommendations) was built — the SDK is intentionally scoped to
  `sdk-web/` per the user's Phase 2 request.
- **Layer 5's CARTA policy is a single-endpoint decision, not a
  full policy engine.** `/api/telemetry` returns one of
  `allow`/`stepup`/`deny` per batch; there is no session-lifecycle
  state machine yet for e.g. automatically re-triggering WebAuthn on
  `stepup` or revoking sessions after repeated `deny`s — that
  orchestration currently lives in the demo app's UI layer only, as a
  visual demonstration, not enforced server-side session control.

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
