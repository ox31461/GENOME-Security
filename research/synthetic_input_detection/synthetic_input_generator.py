"""
synthetic_input_generator.py

Generates two kinds of inter-event timing streams for keystroke/mouse
telemetry:

  1. "Genuine" human-like timing: modeled with the two well-documented
     properties of real human motor control noise that synthetic
     injectors are hard to replicate faithfully:
       a. 1/f ("pink") long-range-correlated noise component, reflecting
          documented fractal/self-similar structure in human motor
          timing (e.g. Slifkin & Newell's work on 1/f noise in force and
          timing output of the human motor system), layered under
       b. a physiological micro-tremor component in the 8-12 Hz band
          (the same band as physiological postural/action tremor),
          which shows up as a periodic micro-oscillation superimposed on
          the raw timing signal when sampled finely enough (we model
          this on mouse-movement timing, where it is well documented in
          HCI/biometrics literature).

  2. "Synthetic" injected timing: what a realistic injection attack
     plausibly looks like today -- Bezier-curve mouse paths (common in
     "humanizer" bot libraries) with independent Gaussian jitter added
     to timings/waypoints to defeat naive variance checks. This
     produces human-*like* first- and second-moment statistics (mean,
     variance) that can fool a naive trust-score check, but it is
     fundamentally i.i.d./white noise at the jitter level: it lacks the
     long-range correlation structure and narrowband tremor signature
     real human motor noise has, because the generator has no
     closed-loop neuromuscular feedback process driving it.

This is a SIMULATION. We are not claiming these exact numeric
parameters characterize all real humans or all real attack tooling --
we are building a reusable, honestly-labeled synthetic dataset to
prototype and evaluate a detector against a realistic class of
injection attack, which is standard practice when no real hardware
capture pipeline exists yet (see attested_input_pipeline.md for the
honest discussion of why real-hardware capture is the next, harder,
step).
"""

from __future__ import annotations

import numpy as np


def _pink_noise(n: int, rng: np.random.Generator) -> np.ndarray:
    """Generate approximate 1/f ('pink') noise of length n via spectral
    shaping of white noise (Voss-McCartney-style via FFT filtering)."""
    white = rng.normal(0, 1, n)
    freqs = np.fft.rfftfreq(n)
    freqs[0] = freqs[1] if len(freqs) > 1 else 1.0  # avoid div by 0 at DC
    spectrum = np.fft.rfft(white)
    # Shape amplitude by 1/sqrt(f) so that power spectrum ~ 1/f.
    shaped = spectrum / np.sqrt(freqs)
    pink = np.fft.irfft(shaped, n)
    pink = (pink - pink.mean()) / (pink.std() + 1e-12)
    return pink


def genuine_keystroke_intervals(n: int, mean_ms: float = 180.0, std_ms: float = 18.0,
                                 seed: int | None = None) -> np.ndarray:
    """
    Simulated genuine human inter-keystroke interval stream (ms).
    Combines: base Gaussian variability + a 1/f long-range-correlated
    component (neuromotor drift/fatigue-like structure) + small
    non-Gaussian heavy-tail component (occasional hesitations), which
    together give real human timing its characteristic higher-order
    moment signature (excess kurtosis, long-range autocorrelation).
    """
    rng = np.random.default_rng(seed)
    base = rng.normal(0, 1, n)
    pink = _pink_noise(n, rng)
    heavy_tail = rng.standard_t(df=3, size=n) * 0.25  # occasional hesitations
    combined = 0.55 * base + 0.35 * pink + 0.10 * heavy_tail
    combined = (combined - combined.mean()) / (combined.std() + 1e-12)
    return mean_ms + std_ms * combined


def synthetic_keystroke_intervals(n: int, mean_ms: float = 180.0, std_ms: float = 18.0,
                                   seed: int | None = None) -> np.ndarray:
    """
    Simulated synthetic/injected inter-keystroke interval stream (ms),
    modeling a 'humanizer' style injector: matches target mean/std
    exactly (an attacker profiling the victim can easily measure these)
    but draws i.i.d. Gaussian jitter per-event with no long-range
    correlation structure and no heavy-tail hesitation component --
    because there is no underlying neuromotor process generating it.
    """
    rng = np.random.default_rng(seed)
    return rng.normal(mean_ms, std_ms, size=n)


def genuine_mouse_timing(n: int, seed: int | None = None) -> np.ndarray:
    """
    Simulated genuine mouse-movement sample timing deltas (ms between
    polled position samples), with an 8-12Hz physiological micro-tremor
    component layered on top of smooth pointer motion -- documented in
    HCI/biometrics literature as a feature that is very hard for
    software-level movement synthesis to replicate because it comes
    from actual muscle/tendon physiology, not cursor path-planning.
    """
    rng = np.random.default_rng(seed)
    t = np.arange(n) / 125.0  # assume ~125Hz sampling, typical mouse poll rate
    tremor_freq = rng.uniform(8.0, 12.0)
    tremor = 0.35 * np.sin(2 * np.pi * tremor_freq * t + rng.uniform(0, 2 * np.pi))
    pink = _pink_noise(n, rng)
    noise = rng.normal(0, 1, n)
    combined = tremor + 0.4 * pink + 0.5 * noise
    base_delta = 8.0  # ms between samples at ~125Hz
    return base_delta + 1.2 * combined


def synthetic_mouse_timing(n: int, seed: int | None = None) -> np.ndarray:
    """
    Simulated synthetic mouse timing: Bezier-curve path planning produces
    smooth, low-order-polynomial velocity profiles; "humanizer" jitter is
    added as independent per-sample Gaussian noise on top. This defeats
    simple mean/variance trust checks but has no narrowband tremor
    signature and no long-range correlation -- the jitter is simply
    white noise bolted onto a deterministic curve.
    """
    rng = np.random.default_rng(seed)
    t = np.arange(n) / 125.0
    # Smooth bezier-like velocity envelope (slow ease-in/ease-out), no tremor.
    envelope = 1.0 + 0.15 * np.sin(2 * np.pi * 0.5 * t)
    jitter = rng.normal(0, 1, n)
    base_delta = 8.0
    return base_delta * envelope + 1.2 * jitter
