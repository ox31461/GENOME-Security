# Phase Plan

## Phase 1 (this repo, current status: complete)

Scope: prove out, with runnable code and real measured results, the two
genuinely novel defenses identified by the research survey as not
already solved elsewhere.

Deliverables:
- `research/baseline_poisoning/` — Asymmetric Learning Gate defense
  module + attack simulation, with real measured attacker-acceptance
  and legitimate-user-acceptance rates comparing naive vs. protected
  baselines.
- `research/synthetic_input_detection/` — synthetic input generator +
  statistical/ML detector, with real measured accuracy/ROC-AUC, plus an
  honest design document on physical-input-origin attestation
  feasibility per OS.
- `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md` — full system design
  and adversary-to-defense mapping, clearly distinguishing "novel, built
  here" vs. "mature, to be integrated" components.

Explicitly NOT in Phase 1 scope (see Phase 2 below): no client SDK, no
server risk engine, no demo application, no actual FIDO2/WebAuthn or
DPoP integration code. Phase 1 is a research/prototype phase focused
entirely on validating the two novel defenses in isolation, with
reproducible simulations rather than production deployment.

## Phase 2 (this repo, current status: complete)

Scope: build the production system around the two novel defenses
proven out in Phase 1, by integrating the mature standards identified
in the research survey rather than reinventing them.

Delivered:

1. **Client SDK** — `sdk-web/`, TypeScript, browser-first (as scoped;
   native desktop modules were explicitly out of scope for this phase
   and remain future work, see below):
   - Keystroke dynamics capture (inter-keydown interval timing only)
     and mouse dynamics capture (inter-`mousemove` interval timing
     only) — deliberately record timing, never key values or cursor
     positions, as a privacy property of the capture layer itself.
   - WebAuthn registration and assertion flows
     (`navigator.credentials.create/get`), requesting a device-bound
     (non-resident/non-syncable-preferring) credential where the
     authenticator supports it, feeding the server's Asymmetric
     Learning Gate anchor-event logic.
   - DPoP (RFC 9449) proof-of-possession generation with a
     non-extractable WebCrypto ES256 keypair, including the RFC 7638
     JWK thumbprint binding used by the server's `cnf.jkt` session
     check.
   - A documented public API (`GenomeClient`) covering
     register/login/telemetry streaming/trust-update subscription in a
     few lines of integration code.
   - Integration of the OS input-path anomaly signals documented in
     `attested_input_pipeline.md` (Raw Input on Windows, evdev/eBPF on
     Linux, Input Monitoring awareness on macOS) is **not** implemented
     in this phase — it remains future work, see below.

2. **Server risk engine** — `server/`, Rust (`axum` + `tokio`):
   - Production port of the Asymmetric Learning Gate
     (`server/src/alg.rs`) and the synthetic-input detector
     (`server/src/detector.rs`, `server/src/dsp.rs`,
     `server/src/synthetic_input.rs`), carrying over the same
     quarantine/anchor-validation thresholds and timing-moment /
     micro-tremor spectral features validated in the Phase 1 Python
     prototypes, with unit test coverage (23/23 tests passing).
   - DPoP (RFC 9449) verification (`server/src/dpop.rs`): JWT proof
     parsing, `htu`/`htm`/`iat` freshness and `jti` replay-window
     checks, access-token binding via `ath` and `cnf.jkt`.
   - FIDO2/WebAuthn registration + assertion verification via the
     maintained `webauthn-rs` crate (no hand-rolled COSE/attestation
     parsing).
   - A telemetry ingestion endpoint (`/api/telemetry`) that runs
     keystroke/mouse timing batches through the detector + trust-score
     pipeline and returns a CARTA-style decision (`allow` / `stepup` /
     `deny`) per the tiers defined in `docs/THREAT_MODEL.md`.
   - An in-memory + SQLite-backed store sufficient for the demo; a real
     deployment needs a proper datastore with durability, backup, and
     multi-instance session-sharing guarantees this does not provide.
   - Post-quantum credential material (ML-DSA/ML-KEM) was **not**
     implemented in this phase — remains future work, see below.

3. **Demo application** — `demo-app/`, a Vite + vanilla TypeScript web
   app wiring the SDK to the server end-to-end: passkey registration,
   passkey login, a live trust-score dial driven by real keystroke/
   mouse telemetry, and a button that injects synthetic-looking
   keystroke timing to visibly demonstrate the detector and decision
   reacting. See `demo-app/README.md` for exact run instructions and
   this phase's honest statement that the synthetic-input defense
   demonstrated here is the statistical detector only, not an
   OS-level attested input pipeline.

Explicitly NOT in Phase 2 scope (carried forward as future work):

- **Validation against real data** (Phase 1's synthetic-vs-synthetic
  evaluation limitation is unchanged): collecting a real, consented
  keystroke/mouse telemetry corpus from genuine users and real
  injection-tool-produced telemetry, and re-validating detector
  accuracy against it before relying on it operationally.
- **Multivariate baseline generalization**: the Asymmetric Learning
  Gate still operates on the single-scalar-feature design validated in
  Phase 1, not a full behavioral feature vector with multivariate
  drift detection (e.g. Mahalanobis distance / subspace methods).
- **Post-quantum credential material**: ML-DSA/ML-KEM per NIST FIPS
  203/204 were not integrated; the server currently relies on
  `webauthn-rs`'s classical (ECDSA/RSA) COSE algorithms and DPoP's
  classical ES256.
- **Native desktop/OS-level input-path signal integration**: the
  `attested_input_pipeline.md` recommendations (Raw Input on Windows,
  evdev/eBPF on Linux, Input Monitoring awareness on macOS) remain a
  design document only; no native module consumes them yet.
- **Production datastore, horizontal scaling, and credential/key
  rotation operations** for the server.

This plan will be updated again if/when a Phase 3 addressing the above
begins.
