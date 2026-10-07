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

## Phase 2 (future work, not yet started)

Scope: build the production system around the two novel defenses
proven out in Phase 1, by integrating the mature standards identified
in the research survey rather than reinventing them.

Planned deliverables:

1. **Client SDK** (likely TypeScript for web, with native modules for
   desktop):
   - Keystroke dynamics capture (dwell/flight time) and mouse dynamics
     capture (movement timing, micro-tremor where samplable), local-only
     raw capture with only derived features leaving the device.
   - Integration of the OS input-path anomaly signals documented in
     `attested_input_pipeline.md` (Raw Input on Windows, evdev/eBPF on
     Linux, Input Monitoring awareness on macOS) as best-effort,
     honestly-partial secondary signals.
   - WebAuthn/FIDO2 registration and assertion flows, feeding
     high-assurance anchor events into the Asymmetric Learning Gate.
   - DPoP (RFC 9449) proof-of-possession generation bound to a
     non-exportable private key.

2. **Server risk engine** (likely Go or Rust for the hot path):
   - Production implementation of the Asymmetric Learning Gate and the
     synthetic-input detector, generalized from the single-feature /
     single-signal Phase 1 prototypes to full feature vectors.
   - DPoP token validation and binding enforcement.
   - A CARTA-aligned policy engine that combines all risk signals
     (behavioral trust score, input-authenticity score, device/session
     binding validity) into session-level decisions: allow, step-up
     (re-trigger WebAuthn), restrict (reduce session privileges), or
     terminate.
   - Post-quantum credential material: ML-DSA for signing, ML-KEM where
     key establishment is needed, per NIST FIPS 203/204.

3. **Demo application**:
   - A small real web app (not a toy) that exercises the full stack:
     WebAuthn registration/login, live keystroke/mouse telemetry capture,
     a trust-score dashboard showing the session's current risk score
     and why (which signals contributed), and a way to simulate/demo
     both defended attacks live (baseline poisoning attempt, synthetic
     input injection attempt) so the defenses are visibly demonstrable,
     not just claimed.

4. **Validation against real data** (addressing Phase 1's honestly
   stated limitation that the synthetic-input detector was evaluated
   synthetic-vs-synthetic): collect a real, consented keystroke/mouse
   telemetry corpus from genuine users, and real injection-tool-produced
   telemetry (from known humanizer libraries), and re-validate detector
   accuracy against that real data before relying on it operationally.

5. **Multivariate baseline generalization**: extend the Asymmetric
   Learning Gate from the single-scalar-feature prototype in Phase 1 to
   a full behavioral feature vector with proper multivariate drift
   detection (e.g. Mahalanobis distance / subspace methods), and add
   lifetime-drift bounding to harden against a patient adaptive attacker
   who paces drift just under the per-batch detection thresholds.

Phase 2 has not started; this plan will be updated as it begins.
