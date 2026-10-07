"""
detector.py

Statistical/ML classifier distinguishing genuine human input timing
from synthetically-generated ("humanizer"-style) injected timing.

Feature justification
----------------------
We deliberately avoid first/second-moment features (mean, variance)
because those are exactly what a competent injector will match to the
victim's profile. Instead we extract features that reflect the
*generating process*, not just its marginal distribution:

  1. Spectral slope (1/f exponent): fit a line to log(power) vs
     log(frequency) of the timing signal's power spectral density.
     Real human motor timing exhibits long-range-correlated ("pink",
     slope near -1) structure; i.i.d. Gaussian jitter is white noise
     (slope near 0). This is the single most discriminating feature in
     our simulation because it targets the structural difference
     between a closed-loop neuromotor process and open-loop jitter.

  2. Excess kurtosis of intervals: genuine human timing has heavier
     tails (occasional hesitations/corrections) than bolted-on Gaussian
     jitter, which is mesokurtic by construction.

  3. Sample entropy (approximate): a measure of signal regularity/
     predictability. We use a simplified approximate-entropy style
     statistic; purely random jitter is typically *more* entropic at
     short lags, while structured physiological signals show
     intermediate complexity. Included as a secondary, weaker signal.

  4. Narrowband spectral power ratio (8-12 Hz band vs total), used only
     for mouse timing: detects the physiological micro-tremor component
     that is specific to real human output and essentially absent from
     a Bezier/jitter generator.

We evaluate with a simple, well-understood logistic regression
classifier (deliberately not a black box) so the discriminating power
of each feature can be inspected directly via its coefficient, and
report accuracy + ROC-AUC via cross-validation on simulated data.
"""

from __future__ import annotations

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.metrics import roc_auc_score, accuracy_score, classification_report, roc_curve

from synthetic_input_generator import (
    genuine_keystroke_intervals,
    synthetic_keystroke_intervals,
    genuine_mouse_timing,
    synthetic_mouse_timing,
)


def _spectral_slope(x: np.ndarray) -> float:
    """Fit log(power) ~ slope * log(freq) + c via least squares; return slope."""
    x = x - x.mean()
    n = len(x)
    spectrum = np.abs(np.fft.rfft(x)) ** 2
    freqs = np.fft.rfftfreq(n)
    # Skip DC and the very top (noise floor) bins.
    mask = (freqs > 0) & (freqs < 0.45)
    f = freqs[mask]
    p = spectrum[mask]
    p = np.clip(p, 1e-12, None)
    log_f = np.log10(f)
    log_p = np.log10(p)
    slope, _ = np.polyfit(log_f, log_p, 1)
    return float(slope)


def _excess_kurtosis(x: np.ndarray) -> float:
    x = x - x.mean()
    m2 = np.mean(x ** 2)
    m4 = np.mean(x ** 4)
    if m2 < 1e-12:
        return 0.0
    return float(m4 / (m2 ** 2) - 3.0)


def _approx_entropy(x: np.ndarray, m: int = 2, r_frac: float = 0.2) -> float:
    """Simplified approximate entropy (ApEn), lower-cost variant."""
    x = np.asarray(x, dtype=float)
    n = len(x)
    r = r_frac * np.std(x)
    if r < 1e-9 or n <= m + 1:
        return 0.0

    def _phi(mm):
        templates = np.array([x[i:i + mm] for i in range(n - mm + 1)])
        count = np.zeros(len(templates))
        for i, t in enumerate(templates):
            dist = np.max(np.abs(templates - t), axis=1)
            count[i] = np.sum(dist <= r)
        count = count / len(templates)
        return np.mean(np.log(np.clip(count, 1e-12, None)))

    return float(_phi(m) - _phi(m + 1))


def _narrowband_ratio(x: np.ndarray, fs: float = 125.0, band=(8.0, 12.0)) -> float:
    x = x - x.mean()
    n = len(x)
    spectrum = np.abs(np.fft.rfft(x)) ** 2
    freqs = np.fft.rfftfreq(n, d=1.0 / fs)
    total = np.sum(spectrum[1:]) + 1e-12
    band_power = np.sum(spectrum[(freqs >= band[0]) & (freqs <= band[1])])
    return float(band_power / total)


def extract_features(x: np.ndarray, include_narrowband: bool) -> list[float]:
    feats = [
        _spectral_slope(x),
        _excess_kurtosis(x),
        _approx_entropy(x),
    ]
    if include_narrowband:
        feats.append(_narrowband_ratio(x))
    return feats


def build_dataset(n_samples_per_class: int, window_len: int, kind: str, seed_offset: int = 0):
    """
    kind: 'keystroke' or 'mouse'
    Returns X (features), y (1 = synthetic, 0 = genuine), and feature names.
    """
    X, y = [], []
    include_narrowband = kind == "mouse"
    for i in range(n_samples_per_class):
        seed_g = 1000 + seed_offset + i
        seed_s = 2000 + seed_offset + i
        if kind == "keystroke":
            genuine = genuine_keystroke_intervals(window_len, seed=seed_g)
            synthetic = synthetic_keystroke_intervals(window_len, seed=seed_s)
        else:
            genuine = genuine_mouse_timing(window_len, seed=seed_g)
            synthetic = synthetic_mouse_timing(window_len, seed=seed_s)
        X.append(extract_features(genuine, include_narrowband))
        y.append(0)
        X.append(extract_features(synthetic, include_narrowband))
        y.append(1)

    names = ["spectral_slope", "excess_kurtosis", "approx_entropy"]
    if include_narrowband:
        names.append("narrowband_8_12hz_ratio")
    return np.array(X), np.array(y), names


def evaluate(kind: str, n_samples_per_class: int = 300, window_len: int = 256):
    X, y, feature_names = build_dataset(n_samples_per_class, window_len, kind)

    clf = LogisticRegression(max_iter=2000)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=7)
    probs = cross_val_predict(clf, X, y, cv=cv, method="predict_proba")[:, 1]
    preds = (probs >= 0.5).astype(int)

    acc = accuracy_score(y, preds)
    auc = roc_auc_score(y, probs)
    report = classification_report(y, preds, target_names=["genuine", "synthetic"])

    clf.fit(X, y)
    coefs = dict(zip(feature_names, clf.coef_[0]))

    return dict(kind=kind, accuracy=acc, auc=auc, report=report, coefs=coefs,
                X=X, y=y, probs=probs, feature_names=feature_names)


def main():
    for kind in ("keystroke", "mouse"):
        result = evaluate(kind)
        print(f"\n{'='*70}\nDetector results for: {kind.upper()} timing\n{'='*70}")
        print(f"Cross-validated accuracy: {result['accuracy']*100:.1f}%")
        print(f"Cross-validated ROC-AUC:  {result['auc']:.4f}")
        print("\nPer-class report:")
        print(result["report"])
        print("Logistic regression coefficients (feature importance / direction):")
        for name, coef in result["coefs"].items():
            print(f"  {name:<28} {coef:+.3f}")

        fpr, tpr, thresh = roc_curve(result["y"], result["probs"])
        # Print a handful of representative ROC points.
        idxs = np.linspace(0, len(fpr) - 1, 6).astype(int)
        print("\nSample ROC curve points (fpr, tpr):")
        for i in idxs:
            print(f"  fpr={fpr[i]:.3f}  tpr={tpr[i]:.3f}  thresh={thresh[i]:.3f}")


if __name__ == "__main__":
    main()
