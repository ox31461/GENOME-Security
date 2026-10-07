# Attested Input Pipeline: Verifying Physical Input Origin

## The problem

Statistical detectors (see `detector.py`) distinguish genuine from
synthetic *timing patterns*, but a sufficiently sophisticated attacker
can shape a synthetic generator to mimic those statistical properties
too — it's an arms race fought entirely in software, on data the
attacker can also observe. The structurally stronger defense is to
verify, at the OS/driver level, that an input event genuinely
originated from a physical input bus interrupt (USB HID report, PS/2
interrupt, Bluetooth HID packet) rather than from a software injection
point (`SendInput`/`uinput`/`CGEvent` and similar OS APIs that any
process with sufficient privilege can call).

**This is a genuinely hard, partially unsolved problem on today's
commodity consumer hardware and OSes.** This document is an honest
accounting of what is and isn't feasible, written so GENOME Security
does not overclaim a capability that doesn't actually exist yet.

## What's NOT solved today

- **No commodity OS ships a standardized, application-visible API that
  cryptographically attests "this input event came from physical
  hardware."** All three major desktop OSes expose input events to
  user-mode applications through APIs that make no distinction between
  hardware-originated and synthetically-injected events once the event
  reaches the point where an application can observe it.
- **Any process with the right privilege level can inject input that is
  indistinguishable, at the API level the application sees, from real
  input**, on Windows (`SendInput`, a kernel-mode filter driver, or a
  virtual HID device created via `vhidmini`/custom drivers), on Linux
  (`/dev/uinput`, which is specifically designed to let user-space
  create convincing virtual input devices), and on macOS
  (`CGEventPost`/`IOHIDUserDevice`).
- There is no cross-platform, vendor-neutral standard analogous to
  WebAuthn/FIDO2 for "attested human input device" the way there is for
  authenticators. This would require coordinated hardware + firmware +
  OS kernel + driver-stack work across the industry; it does not exist
  today.

## What IS partially feasible today (with caveats)

### Windows
- **Raw Input API (`WM_INPUT` / `GetRawInputData`) with device handle
  tracking**: lets an application distinguish *which logical HID device*
  generated an event and inspect its device path/vendor-product ID.
  This raises the bar (an injector must either spoof a plausible HID
  device identity or route through an existing real device's handle)
  but does **not** cryptographically prove hardware origin — a
  sufficiently privileged kernel-mode driver can still present a fake
  HID device that Raw Input reports as if it were real hardware.
- **Protected Process Light / kernel-mode anti-cheat style drivers**
  (the approach used by commercial anti-cheat software, e.g. Easy
  Anti-Cheat, BattlEye, Vanguard) install a signed kernel driver that
  hooks the HID stack lower than user-mode injection APIs and can flag
  known injection techniques (virtual HID creation, `SendInput` call
  patterns, suspicious driver loads). This is the most capable
  practical approach on Windows today, but it: (a) requires a
  kernel-mode driver with attendant security/compatibility/support
  burden, (b) is fundamentally a signature/heuristic detection of known
  injection techniques, not a cryptographic proof, and (c) is routinely
  bypassed by well-resourced cheat/malware developers specifically
  targeting anti-cheat drivers — the same arms race, one layer down.
- **TPM-backed attestation covers the platform's boot/driver state, not
  individual input events.** Windows' Secure Boot + Measured Boot +
  TPM attestation can increase confidence that no unsigned kernel driver
  is loaded at boot, which narrows (but does not eliminate — e.g.
  `/dev/uinput`-equivalent user-mode techniques, BYOVD "bring your own
  vulnerable driver" attacks, or pre-existing signed virtualization/
  remote-input software) the feasible injection techniques. It is not a
  per-event attestation.

### Linux
- **`udev`/`evdev` device enumeration** lets an application see the
  originating device node (`/dev/input/eventN`) and its reported
  vendor/product IDs, but `/dev/uinput` is an intentionally-supported
  kernel facility for creating virtual input devices indistinguishable,
  at the evdev API level, from real ones (this is by design — it's how
  legitimate remote-desktop and accessibility software works). A
  `CAP_SYS_ADMIN`-privileged attacker can create a virtual device and
  there is no standard in-kernel attestation that evdev consumers can
  check.
- **eBPF-based kernel-level monitoring** can watch for creation of new
  `uinput` devices or anomalous input-subsystem driver loads as a
  detection signal, similar in spirit to the Windows kernel-driver
  approach, with the same fundamental limitation: it's heuristic
  detection of known techniques, not cryptographic proof.

### macOS
- **Input Monitoring / Accessibility permission prompts** require
  explicit user consent before an application can observe or synthesize
  global input events, which raises the bar for *silent* injection (the
  user would see a permission prompt the first time), but a
  compromised, already-permitted process (e.g. a legitimately installed
  remote-access tool, or malware that convinces the user to grant the
  permission) is not detected by this mechanism at the point of
  generating events.
- Apple does not expose a hardware-attestation API for individual HID
  events to third-party applications.

## Recommended practical architecture, given these constraints (Phase 2 target)

Given that cryptographic per-event hardware attestation is not
available on commodity OSes today, GENOME Security's practical,
honestly-scoped architecture is **defense in depth, not a single
silver bullet**:

1. **Primary layer — statistical/structural detection** (this repo's
   `detector.py` approach), continuously run against live telemetry,
   looking for the generative-process signatures (spectral slope,
   tremor band, higher moments) that are hard for an injector to fake
   without itself modeling the same physiological processes.
2. **Secondary layer — OS input-path anomaly signals**, consumed as
   additional risk-score inputs, not as a binary gate:
   - Windows: Raw Input device-handle stability/consistency checks,
     and (optionally, for high-assurance deployments willing to accept
     the operational cost) a signed kernel-mode input-path monitor
     similar to anti-cheat drivers.
   - Linux: eBPF monitoring for new `uinput` device creation events
     correlated in time with suspicious authentication activity.
   - macOS: monitoring for newly-granted Input Monitoring/Accessibility
     permissions correlated with suspicious activity, via
     `TCC.db`/`tccutil` introspection (requires appropriate entitlement/
     admin context).
3. **Tertiary layer — the asymmetric learning gate's existing design
   already limits the blast radius of a successful injection**: because
   continuous telemetry (genuine or injected) never updates the
   baseline, even a perfect injection attack that fully evades both
   layers above can at most achieve the SAME outcome as a replay/mimicry
   attack against a frozen baseline — it cannot poison the baseline
   itself, which is the more dangerous long-term threat.
4. **Explicit non-goal for Phase 1/2**: claiming we can cryptographically
   *prove* any given input event came from physical hardware on
   commodity Windows/Linux/macOS. We do not believe this is honestly
   achievable without new industry-wide hardware/firmware/OS standards
   work (an interesting parallel to how WebAuthn required coordinated
   hardware + OS + browser work over several years). We will track and
   adopt any such standard if/when one emerges, rather than ship a false
   claim of solving it today.

## Summary table

| Layer | Confidence it detects injection | Bypassable by |
|---|---|---|
| Statistical timing detector | Moderate (88-95% in our simulation, synthetic-vs-synthetic) | Adversary who models the same structural features (1/f, tremor) |
| Windows Raw Input device tracking | Low-moderate | Kernel-mode virtual HID device spoofing device identity |
| Kernel-mode input-path monitor (anti-cheat style) | Moderate-high, but heuristic | Novel/unknown injection technique, BYOVD, driver-level compromise |
| Linux eBPF uinput monitoring | Moderate | Root-level compromise disabling/evading the monitor itself |
| macOS Input Monitoring consent | Low (one-time gate, not continuous) | Pre-granted permission on already-compromised/trusted process |
| **True cryptographic hardware attestation of individual input events** | **Not available on any commodity OS today** | N/A — doesn't exist to bypass |
