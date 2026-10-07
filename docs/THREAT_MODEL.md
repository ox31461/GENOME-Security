# Threat Model

This document maps specific adversaries and attack techniques to the
specific defenses GENOME Security provides (or, where honestly
incomplete, the defenses it is designed to layer with). Severity/
likelihood ratings are qualitative judgments for prioritization, not
formal risk-quantification.

## Adversary 1: Remote attacker with a stolen bearer token

**Capability**: obtained an OAuth/session bearer token via XSS, a
malicious browser extension, or a leaked log, without compromising the
victim's device.

**Attack**: replay the token from attacker-controlled infrastructure to
impersonate the victim's session.

**Defense**: DPoP (RFC 9449) token binding (Phase 2, standards
integration). A DPoP-bound token is useless without the corresponding
private key, which never leaves the device (and ideally never leaves a
hardware-backed keystore). This defense is **mature and standardized**;
GENOME Security's job is correct integration, not invention.

**Residual risk**: DPoP defends against token *replay*, not against an
attacker who has also compromised the originating device (see
Adversary 3).

---

## Adversary 2: Session hijacker running code on the victim's device

**Capability**: malware or a malicious process running under the
victim's already-authenticated session (e.g. after a drive-by
compromise), with the ability to read the current valid DPoP-bound
token/cookie and make authenticated requests, and/or inject synthetic
input events.

**Attack A — passive session riding**: just use the existing valid
session/token directly. **Defense**: continuous behavioral risk scoring
(Layer 3/4) — if the attacker's actions produce behavior statistically
inconsistent with the established (frozen) baseline, the trust score
drops and the session is challenged/restricted. This is the core value
proposition of continuous auth generally, not something GENOME
Security invented, but it's the reason continuous auth exists at all.

**Attack B — adversarial baseline poisoning ("boiling the frog")**:
rather than acting obviously different, the attacker injects behavior
that starts close to the victim's baseline and *slowly drifts* toward
their own natural behavior over many sessions, specifically targeting
systems whose baseline continuously self-updates from ambient
telemetry, with the goal of eventually making their own natural
behavior pass as "normal."

**Defense (NOVEL — this is Phase 1's primary contribution)**: the
**Asymmetric Learning Gate** (`research/baseline_poisoning/`). The
baseline is structurally prevented from ever updating off ambient
telemetry, no matter how gradual or statistically unremarkable the
drift looks. It can only accept new baseline data staged through a
quarantine buffer and validated across multiple independent
high-assurance anchor events (hardware-backed WebAuthn assertions),
which the attacker cannot forge remotely. Measured in our simulation:
this reduces the attacker's eventual acceptance rate from 95.4%
(naive, unprotected baseline) to 2.8% (ALG-protected) over the same
attack timeline — see `research/baseline_poisoning/README.md` for the
full run.

**Residual risk**: if the attacker also has physical possession of the
*enrolled hardware authenticator itself* (see Adversary 5), anchor
events stop being a reliable "only the real user" signal, and this
defense degrades to the strength of whatever secondary factor protects
authenticator use (PIN/biometric unlock on the authenticator). Also:
an adaptive attacker who knows the gate's exact parameters could in
principle pace drift to stay just under detection thresholds over a
much longer horizon than simulated here — bounding *lifetime* drift
without re-enrollment is flagged as Phase 2 hardening work, not yet
implemented.

**Attack C — synthetic input injection**: rather than driving real
input devices, the attacker's malware directly injects synthetic
keystroke/mouse events via OS-level APIs (`SendInput`, `/dev/uinput`,
`CGEventPost`) using "humanizer" libraries that add Bezier-curve mouse
paths and Gaussian-noise timing, specifically engineered to pass a
naive trust-score check that only looks at mean/variance.

**Defense (NOVEL — this is Phase 1's other primary contribution)**: a
two-layer approach documented and prototyped in
`research/synthetic_input_detection/`:
1. A statistical/ML detector targeting structural generative-process
   signatures (1/f spectral slope, physiological tremor band, higher
   moments) rather than first/second-moment statistics an injector can
   trivially match. Measured: 88.3%/94.5% accuracy, 0.958/0.990 AUC for
   keystroke/mouse respectively, in our synthetic-vs-synthetic
   evaluation (see that folder's README for full numbers and honest
   caveats about this being simulation-vs-simulation, not yet validated
   against real captured human/malware data).
2. OS input-path anomaly signals as a secondary, heuristic layer
   (Raw Input device tracking on Windows, eBPF `uinput` monitoring on
   Linux, Input Monitoring consent tracking on macOS) — see
   `attested_input_pipeline.md` for the full per-OS honest breakdown.

**Residual risk — stated plainly**: there is **no commodity-OS
mechanism today that cryptographically proves an input event
originated from physical hardware** rather than software injection.
This is a genuinely open problem industry-wide, not something GENOME
Security claims to have solved. Our mitigation is defense-in-depth
(statistical detection + heuristic OS signals + the fact that even a
successful injection cannot poison the baseline thanks to Defense B
above), not a single structural guarantee. See
`research/synthetic_input_detection/attested_input_pipeline.md`.

---

## Adversary 3: Attacker with full device compromise (root/admin)

**Capability**: full control of the victim's OS, including kernel-level
access.

**Attack**: bypass any user-mode detection entirely, including this
system's own trust-scoring code.

**Defense**: fundamentally out of scope for a software-only behavioral
biometric system — this is a general endpoint-security problem (EDR,
secure boot, attested boot state). GENOME Security's defenses assume
the attacker does **not** have kernel/root-level control of the victim
device; this is stated explicitly rather than implied, because it is
an important scope boundary. A hardware root of trust (PUFs, per the
Phase 2 standards-integration list) raises the bar for persistence but
does not eliminate a sufficiently resourced kernel-level attacker.

---

## Adversary 4: Attacker attempting credential phishing

**Capability**: tricks the victim into authenticating on an
attacker-controlled site.

**Defense**: FIDO2/WebAuthn's origin-binding makes device-bound
passkeys phishing-resistant by construction — the authenticator will
not produce a valid assertion for the wrong origin. **Mature and
standardized**; Phase 2 integration work, not invention.

---

## Adversary 5: Physical device/authenticator theft

**Capability**: physically steals the victim's device and/or hardware
authenticator (security key, platform authenticator).

**Defense**: hardware authenticator PIN/biometric unlock (standard
WebAuthn user-verification requirement), combined with continuous
behavioral risk scoring post-unlock (an attacker who has the physical
key but not the victim's behavioral patterns will still diverge from
the frozen baseline during actual use, and because of the Asymmetric
Learning Gate, cannot use that post-unlock access to retrain the
baseline toward their own behavior with just one or a few stolen-device
sessions — `required_anchor_batches` in our implementation requires
multiple independent anchor-validated batches that are also mutually
statistically consistent before any merge occurs).

**Residual risk**: a sustained physical theft (attacker retains the
device/key for an extended period, authenticating repeatedly) is the
scenario where our defenses are weakest, since the attacker genuinely
does have hardware-backed anchor events available to them repeatedly.
This is stated honestly as a hard case, not papered over: continuous
behavioral scoring would still generate elevated risk during the
divergent sessions themselves (limiting the blast radius before any
possible baseline merge), but a determined, patient physical-theft
attacker who also studies and mimics the victim's behavior is a threat
this system reduces but does not eliminate.

---

## Adversary 6: "Harvest now, decrypt later" (quantum-capable future
adversary)

**Capability**: records encrypted traffic/credential material today,
decrypts it once cryptographically-relevant quantum computers exist.

**Defense**: post-quantum ML-KEM (key encapsulation) / ML-DSA
(signatures), standardized by NIST (FIPS 203/204). **Mature and
standardized**; Phase 2 integration work, not invention.

---

## Summary table

| Adversary | Attack | Defense | Status |
|---|---|---|---|
| Remote token thief | Token replay | DPoP (RFC 9449) | Phase 2 (standards integration) |
| Session rider | Act differently | Continuous risk scoring | Phase 2 (standards integration, framework exists) |
| Session rider | Baseline poisoning | **Asymmetric Learning Gate** | **Phase 1 — built & measured here** |
| Session rider | Synthetic input injection | **Statistical detector + OS heuristics** | **Phase 1 — built & measured here** |
| Root/kernel attacker | Full compromise | Out of scope (endpoint security) | Not addressed |
| Phisher | Credential phishing | FIDO2/WebAuthn origin binding | Phase 2 (standards integration) |
| Physical thief | Device/key theft | Hardware unlock + behavioral scoring | Partial, honestly incomplete for sustained theft |
| Quantum-capable future adversary | Harvest now, decrypt later | ML-KEM/ML-DSA | Phase 2 (standards integration) |
