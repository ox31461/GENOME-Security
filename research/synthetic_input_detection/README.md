# Synthetic Input Injection Detection — Research Prototype

This folder contains a runnable simulation and detector prototype for
distinguishing **genuine human input timing** from **synthetically
generated / injected input timing** (e.g. malware using a virtual
input driver with a "humanizer" library that draws Bezier-curve mouse
paths and adds Gaussian jitter to keystroke timing, specifically to
defeat naive behavioral-biometric trust checks).

## Files

- `synthetic_input_generator.py` — generates both classes of signal for
  keystroke inter-event intervals and mouse sample timing.
- `detector.py` — extracts structural (not just mean/variance) features
  and evaluates a logistic regression classifier via cross-validation.
- `attested_input_pipeline.md` — honest design discussion of what's
  feasible today, per OS, for verifying an input event actually
  originated from a physical input bus rather than software injection.

## How to run

```bash
pip install -r ../requirements.txt
cd research/synthetic_input_detection
python detector.py
```

## Why these features (not mean/variance)

A competent injector can trivially match the victim's mean and standard
deviation — those are the easiest statistics to profile and replicate.
So the detector instead targets properties of the **generating
process**:

1. **Spectral slope (1/f exponent)** — log(power) vs log(frequency)
   slope of the timing signal's power spectrum. Human motor timing
   output has long documented 1/f ("pink noise") structure (e.g.
   Slifkin & Newell's work on long-range correlation in human motor
   output); independent per-event Gaussian jitter is white noise (flat
   spectrum, slope ≈ 0). This was the single strongest feature in our
   run (largest logistic regression coefficient magnitude for both
   keystroke and mouse models).
2. **Excess kurtosis** — real timing has heavier tails from occasional
   hesitations/corrections; synthetic Gaussian jitter is mesokurtic by
   construction.
3. **Approximate entropy** — a regularity/complexity measure; included
   as a secondary, weaker signal.
4. **Narrowband 8–12Hz spectral power ratio** (mouse only) — detects the
   physiological micro-tremor band documented in HCI/biometrics
   literature on genuine pointer motion; a Bezier-curve path generator
   has no equivalent physiological process driving it.

## Actual results from a real run (5-fold stratified cross-validation, 300 samples/class/kind)

```
======================================================================
Detector results for: KEYSTROKE timing
======================================================================
Cross-validated accuracy: 88.3%
Cross-validated ROC-AUC:  0.9583

              precision    recall  f1-score   support
     genuine       0.88      0.89      0.88       300
   synthetic       0.89      0.87      0.88       300
    accuracy                           0.88       600

Logistic regression coefficients:
  spectral_slope               +9.184
  excess_kurtosis              +0.013
  approx_entropy               -0.370

======================================================================
Detector results for: MOUSE timing
======================================================================
Cross-validated accuracy: 94.5%
Cross-validated ROC-AUC:  0.9901

              precision    recall  f1-score   support
     genuine       0.94      0.95      0.95       300
   synthetic       0.95      0.94      0.94       300
    accuracy                           0.94       600

Logistic regression coefficients:
  spectral_slope               +7.785
  excess_kurtosis              -0.976
  approx_entropy               +0.169
  narrowband_8_12hz_ratio      -7.329
```

(Full output including ROC curve sample points is reproducible by
running `python detector.py`.)

## What the results mean

- The spectral-slope feature dominates both models (largest absolute
  coefficient), confirming the hypothesis: the presence/absence of
  long-range-correlated ("pink") structure is the most reliable
  discriminator between a closed-loop human neuromotor process and an
  open-loop jitter generator, even when both are tuned to match the
  same mean/variance.
- Adding the narrowband 8–12Hz tremor feature for mouse timing pushes
  accuracy from the keystroke-only-feature-set range (~88%) up to 94.5%
  and AUC to 0.99 — physiological tremor is a strong, fairly
  injector-resistant signal when the channel (mouse polling) actually
  carries it.
- 88–95% accuracy against *this* generator is a meaningful result but
  **not a production-ready universal detector** — see limitations below.

## Honest limitations

- **This is a synthetic-vs-synthetic evaluation.** Both the "genuine"
  and "synthetic" classes in this prototype are *simulated* signals;
  we do not yet have a real captured corpus of human keystroke/mouse
  telemetry to validate the "genuine" model against actual humans, nor
  real malware/humanizer tooling to validate the "synthetic" model
  against. The 1/f and 8-12Hz tremor properties modeled here are based
  on published human-motor-control literature, but our simulated
  genuine-signal generator is itself just a model, not real data. A
  production system must retrain and re-validate against real captured
  telemetry (Phase 2 scope) before these accuracy numbers can be relied
  upon operationally.
- **This evaluates one specific injection strategy** (Bezier-curve path
  + i.i.d. Gaussian jitter). A more sophisticated adversary could, in
  principle, shape their jitter generator to also exhibit 1/f spectral
  characteristics (e.g. by filtering white noise, exactly as our own
  `_pink_noise` helper does) and even synthesize a fake tremor band.
  This is a fundamental arms-race limitation of any purely statistical
  detector operating on software-visible timing data: if an adversary
  can measure what the detector measures, they can eventually fit it.
  This is exactly why Phase 1 also pursues the complementary, structurally
  different defense of **verifying the input's physical origin**
  (see `attested_input_pipeline.md`) rather than relying on statistical
  detection alone.
- Our feature extraction is intentionally simple/interpretable
  (3–4 engineered features + logistic regression) rather than a deep
  model over raw waveforms, which likely leaves accuracy on the table
  but keeps the decision auditable — a deliberate tradeoff for a
  security-critical gate.
