//! Synthetic + genuine input timing generators — Rust port of
//! `research/synthetic_input_detection/synthetic_input_generator.py`,
//! used here (a) to train/validate the production detector at startup
//! with the same feature methodology as the validated Python prototype,
//! and (b) to power the demo app's "inject synthetic-looking input"
//! step-up simulation button.

use crate::dsp::pink_noise;
use rand::Rng;
use rand_distr::{Distribution, Normal, StandardNormal, StudentT};

/// Simulated genuine human inter-keystroke interval stream (ms).
/// Combines base Gaussian variability + a 1/f long-range-correlated
/// component + a small heavy-tailed hesitation component, mirroring the
/// Python prototype's `genuine_keystroke_intervals`.
pub fn genuine_keystroke_intervals<R: Rng>(rng: &mut R, n: usize, mean_ms: f64, std_ms: f64) -> Vec<f64> {
    let base: Vec<f64> = (0..n).map(|_| StandardNormal.sample(rng)).collect();
    let white: Vec<f64> = (0..n).map(|_| StandardNormal.sample(rng)).collect();
    let pink = pink_noise(&white);
    let t_dist = StudentT::new(3.0).unwrap();
    let heavy_tail: Vec<f64> = (0..n).map(|_| t_dist.sample(rng) * 0.25).collect();

    let mut combined: Vec<f64> = (0..n)
        .map(|i| 0.55 * base[i] + 0.35 * pink[i] + 0.10 * heavy_tail[i])
        .collect();
    standardize(&mut combined);
    combined.iter().map(|&c| mean_ms + std_ms * c).collect()
}

/// Simulated synthetic/injected inter-keystroke interval stream (ms):
/// i.i.d. Gaussian jitter, matching the target mean/std an attacker can
/// easily profile, but with no long-range correlation or heavy tail.
pub fn synthetic_keystroke_intervals<R: Rng>(rng: &mut R, n: usize, mean_ms: f64, std_ms: f64) -> Vec<f64> {
    let dist = Normal::new(mean_ms, std_ms).unwrap();
    (0..n).map(|_| dist.sample(rng)).collect()
}

/// Simulated genuine mouse-movement sample timing deltas (ms), with an
/// 8-12Hz physiological micro-tremor component layered on smooth motion.
pub fn genuine_mouse_timing<R: Rng>(rng: &mut R, n: usize) -> Vec<f64> {
    let fs = 125.0_f64;
    let tremor_freq = rng.gen_range(8.0..12.0);
    let phase = rng.gen_range(0.0..(2.0 * std::f64::consts::PI));
    let t: Vec<f64> = (0..n).map(|i| i as f64 / fs).collect();
    let tremor: Vec<f64> = t
        .iter()
        .map(|&ti| 0.35 * (2.0 * std::f64::consts::PI * tremor_freq * ti + phase).sin())
        .collect();
    let white: Vec<f64> = (0..n).map(|_| StandardNormal.sample(rng)).collect();
    let pink = pink_noise(&white);
    let noise: Vec<f64> = (0..n).map(|_| StandardNormal.sample(rng)).collect();

    let combined: Vec<f64> = (0..n)
        .map(|i| tremor[i] + 0.4 * pink[i] + 0.5 * noise[i])
        .collect();
    let base_delta = 8.0;
    combined.iter().map(|&c| base_delta + 1.2 * c).collect()
}

/// Simulated synthetic mouse timing: smooth Bezier-like velocity
/// envelope with independent Gaussian jitter bolted on top, and no
/// tremor-band signature.
pub fn synthetic_mouse_timing<R: Rng>(rng: &mut R, n: usize) -> Vec<f64> {
    let fs = 125.0_f64;
    let t: Vec<f64> = (0..n).map(|i| i as f64 / fs).collect();
    let envelope: Vec<f64> = t
        .iter()
        .map(|&ti| 1.0 + 0.15 * (2.0 * std::f64::consts::PI * 0.5 * ti).sin())
        .collect();
    let jitter: Vec<f64> = (0..n).map(|_| StandardNormal.sample(rng)).collect();
    let base_delta = 8.0;
    (0..n).map(|i| base_delta * envelope[i] + 1.2 * jitter[i]).collect()
}

fn standardize(x: &mut [f64]) {
    let n = x.len() as f64;
    let mean = x.iter().sum::<f64>() / n;
    let var = x.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
    let std = var.sqrt().max(1e-12);
    for v in x.iter_mut() {
        *v = (*v - mean) / std;
    }
}
