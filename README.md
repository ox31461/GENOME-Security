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
  layers, data flow, and how Phase 1 and Phase 2 fit the eventual full
  stack, including honest divergences from the original sketch.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — adversary model
  mapping each threat to its specific defense, stated honestly
  including residual risk.
- [`docs/PHASE_PLAN.md`](docs/PHASE_PLAN.md) — what Phase 1 and Phase 2
  cover, and what remains as future work.

## What's in this repo

```
research/
  baseline_poisoning/          # Asymmetric Learning Gate: the defense
                                # against adversarial baseline poisoning
  synthetic_input_detection/   # Statistical detector for synthetic
                                # input injection + honest OS-attestation
                                # feasibility writeup
server/                        # Rust (axum) production risk-engine:
                                # ALG + detector ports, DPoP RFC 9449,
                                # FIDO2/WebAuthn (webauthn-rs), telemetry
                                # ingestion + CARTA-style decisions
sdk-web/                       # TypeScript browser client SDK:
                                # WebAuthn, DPoP proof generation,
                                # keystroke/mouse telemetry capture
demo-app/                      # Vite web app wiring sdk-web to server
                                # end-to-end, with a live trust dial
```

Both research modules are real, runnable Python with real measured
results from actually running the code (not fabricated numbers) — see
each folder's own README for the full output and honest discussion of
limitations. `server/`, `sdk-web/`, and `demo-app/` are real, building,
tested Rust/TypeScript — see each folder's own README for exact run
instructions.

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

For the Phase 2 production system (server + SDK + demo app), see
[`server/README.md`](server/README.md) and
[`demo-app/README.md`](demo-app/README.md) for full setup notes and the
end-to-end walkthrough:

```bash
# 1. Server (Rust) — listens on http://localhost:8080
cd server
cargo run

# 2. SDK (TypeScript) — build once, or after SDK changes
cd ../sdk-web
npm install && npm run build

# 3. Demo app (Vite) — open the printed URL as "localhost", not "127.0.0.1"
cd ../demo-app
npm install && npm run dev
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

**Phase 2 is complete.** The production system around Phase 1's
defenses is built, builds and runs cleanly, and was exercised
end-to-end:

- `server/` (Rust, axum): production ports of the Asymmetric Learning
  Gate and synthetic-input detector, DPoP (RFC 9449) proof
  verification, FIDO2/WebAuthn via `webauthn-rs`, and a
  `/api/telemetry` ingestion endpoint returning CARTA-style
  allow/stepup/deny decisions. `cargo build` succeeds; `cargo test`
  passes 23/23; `cargo run` boots, trains both detectors with real
  measured holdout metrics (keystroke accuracy 0.817 / AUC 0.889,
  mouse accuracy 0.883 / AUC 0.981), and serves on
  `http://localhost:8080`.
- `sdk-web/` (TypeScript): a browser-first client SDK — WebAuthn
  registration/login, WebCrypto-based DPoP proof generation,
  keystroke/mouse interval-timing capture (never key values or cursor
  positions). `tsc --noEmit` is clean, the `tsup` ESM+CJS+`.d.ts` build
  succeeds, and its DPoP/base64url unit tests pass 4/4.
  See [`sdk-web/README.md`](sdk-web/README.md).
- `demo-app/` (Vite + TypeScript): wires the SDK to the server
  end-to-end — passkey registration, passkey login, a live trust-score
  dial driven by real telemetry responses, and a button to simulate a
  synthetic-input injection attack. Typechecks and builds cleanly; the
  dev server and the Rust server were run together and manually
  verified serving correctly (health check, page load, API wiring).
  See [`demo-app/README.md`](demo-app/README.md) for exact run
  instructions and its own honest-limitations statement (the
  synthetic-input defense demonstrated is the statistical detector
  only, not an OS-level attested input pipeline).

Deliberately deferred as future work (see `docs/PHASE_PLAN.md` and
`docs/ARCHITECTURE.md`'s "Phase 2 divergences" section for the full
list): post-quantum ML-KEM/ML-DSA credential material, attested
(non-syncable-enforced) WebAuthn registration, validation of the
detector against real (not synthetic) user and attack telemetry, a
multivariate generalization of the Asymmetric Learning Gate beyond its
current single-scalar-feature design, and native desktop/OS-level
input-path signal integration.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE). Chosen for its explicit
patent grant, which is a relevant consideration for a security project
that may develop defensive techniques worth protecting from patent
trolling while remaining fully open source.
