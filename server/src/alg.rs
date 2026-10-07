//! Asymmetric Learning Gate (ALG) — production Rust port of the validated
//! Python prototype in `research/baseline_poisoning/asymmetric_learning_gate.py`.
//!
//! Defends against adversarial baseline poisoning ("boiling the frog"):
//! the live behavioral baseline is NEVER updated from ambient/continuous
//! telemetry. It only ever accepts candidate updates immediately following
//! a verified high-assurance anchor event (a hardware-backed WebAuthn
//! assertion), and even then stages them in a quarantine buffer that must
//! be statistically validated across multiple such anchor events before
//! being merged into the live baseline.
//!
//! The thresholds below (`required_anchor_batches`, `max_batch_z`,
//! `max_drift_trend`, `ema_alpha`) are carried over unchanged from the
//! Python prototype that was validated in `research/baseline_poisoning/`,
//! where the same defaults reduced a slow-poisoning attacker's acceptance
//! rate from 95.4% (naive baseline) to 2.8% (ALG-protected) over a
//! 39-round attack simulation.

use serde::{Deserialize, Serialize};

/// A batch of samples collected after one high-assurance anchor event,
/// queued in the quarantine buffer awaiting cross-batch validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineBatch {
    pub mean: f64,
    pub std: f64,
    pub n: usize,
}

/// Outcome of submitting an anchor-gated batch to the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateOutcome {
    /// Batch mean was too far (> max_batch_z) from the current live
    /// baseline to even be queued; a single anchor event, however
    /// cryptographically strong, can never alone justify a large jump.
    Rejected,
    /// Batch queued in quarantine; not enough corroborating batches yet.
    Queued,
    /// Quarantine contents were promoted into the live baseline.
    Merged,
    /// A monotonic drift trend was detected across queued batches
    /// (characteristic of a slow-poisoning attack); the quarantine was
    /// reset rather than promoted.
    DriftReset,
}

/// The Asymmetric Learning Gate for a single scalar behavioral feature.
/// In production this generalizes to a feature vector / covariance
/// update; Phase 1/2 model one scalar feature for a clear, auditable
/// first implementation (see docs/PHASE_PLAN.md for the multivariate
/// generalization planned for later hardening work).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsymmetricLearningGate {
    pub mean: f64,
    pub std: f64,
    required_anchor_batches: usize,
    max_batch_z: f64,
    max_drift_trend: f64,
    ema_alpha: f64,
    quarantine: Vec<QuarantineBatch>,
    pub merges: u64,
    pub rejected_batches: u64,
    pub drift_resets: u64,
}

impl AsymmetricLearningGate {
    /// Construct a gate with the validated Phase 1 defaults.
    pub fn new(initial_mean: f64, initial_std: f64) -> Self {
        Self {
            mean: initial_mean,
            std: initial_std,
            required_anchor_batches: 3,
            max_batch_z: 3.0,
            max_drift_trend: 0.6,
            ema_alpha: 0.35,
            quarantine: Vec::new(),
            merges: 0,
            rejected_batches: 0,
            drift_resets: 0,
        }
    }

    /// Construct a gate with explicit (non-default) parameters, for
    /// testing or deployment-specific tuning.
    pub fn with_params(
        initial_mean: f64,
        initial_std: f64,
        required_anchor_batches: usize,
        max_batch_z: f64,
        max_drift_trend: f64,
        ema_alpha: f64,
    ) -> Self {
        Self {
            mean: initial_mean,
            std: initial_std,
            required_anchor_batches,
            max_batch_z,
            max_drift_trend,
            ema_alpha,
            quarantine: Vec::new(),
            merges: 0,
            rejected_batches: 0,
            drift_resets: 0,
        }
    }

    /// Continuous telemetry path (read-only w.r.t. the baseline): return a
    /// risk z-score of `sample` against the CURRENT frozen baseline.
    /// Continuous telemetry only ever calls this; it never mutates state.
    pub fn trust_score(&self, sample: f64) -> f64 {
        if self.std <= 1e-9 {
            return if (sample - self.mean).abs() < 1e-9 {
                0.0
            } else {
                f64::INFINITY
            };
        }
        (sample - self.mean).abs() / self.std
    }

    /// High-assurance anchor path: the ONLY path that can ever mutate the
    /// baseline, and only through the quarantine gate below. Called with a
    /// short window of telemetry collected immediately following a
    /// verified high-assurance anchor event (hardware-backed WebAuthn
    /// assertion).
    pub fn submit_anchor_batch(&mut self, samples: &[f64]) -> GateOutcome {
        assert!(!samples.is_empty(), "anchor batch must not be empty");

        let n = samples.len();
        let batch_mean = samples.iter().sum::<f64>() / n as f64;
        let batch_std = if n > 1 {
            let var = samples
                .iter()
                .map(|x| (x - batch_mean).powi(2))
                .sum::<f64>()
                / (n as f64 - 1.0);
            var.sqrt()
        } else {
            self.std
        };

        // Step 1: hard outlier gate against the CURRENT live baseline.
        let z = self.trust_score(batch_mean);
        if z > self.max_batch_z {
            self.rejected_batches += 1;
            return GateOutcome::Rejected;
        }

        self.quarantine.push(QuarantineBatch {
            mean: batch_mean,
            std: batch_std,
            n,
        });

        // Step 2: drift-trend check across queued batches. A poisoning
        // attacker needs many anchor events and will tend to produce a
        // monotonic walk away from the original baseline.
        if self.quarantine.len() >= 2 {
            let means: Vec<f64> = self.quarantine.iter().map(|b| b.mean).collect();
            let diffs: Vec<f64> = means.windows(2).map(|w| w[1] - w[0]).collect();
            if diffs.len() >= 2 {
                let all_pos = diffs.iter().all(|&d| d > 0.0);
                let all_neg = diffs.iter().all(|&d| d < 0.0);
                let same_sign = all_pos || all_neg;
                let total_move = (means[means.len() - 1] - means[0]).abs();
                if same_sign
                    && self.std > 1e-9
                    && (total_move / self.std) > (self.max_drift_trend * diffs.len() as f64)
                {
                    self.quarantine.clear();
                    self.drift_resets += 1;
                    return GateOutcome::DriftReset;
                }
            }
        }

        // Step 3: promotion check -- need enough independent
        // anchor-validated batches that are mutually consistent.
        if self.quarantine.len() >= self.required_anchor_batches {
            let means: Vec<f64> = self.quarantine.iter().map(|b| b.mean).collect();
            let mean_of_means = means.iter().sum::<f64>() / means.len() as f64;
            let spread = if means.len() > 1 {
                let var = means
                    .iter()
                    .map(|x| (x - mean_of_means).powi(2))
                    .sum::<f64>()
                    / (means.len() as f64 - 1.0);
                var.sqrt()
            } else {
                0.0
            };

            let consistent = self.std <= 1e-9 || (spread / self.std.max(1e-9)) < 1.0;
            if consistent {
                let new_mean = mean_of_means;
                self.mean = (1.0 - self.ema_alpha) * self.mean + self.ema_alpha * new_mean;
                let new_std =
                    self.quarantine.iter().map(|b| b.std).sum::<f64>() / self.quarantine.len() as f64;
                self.std = (1.0 - self.ema_alpha) * self.std + self.ema_alpha * new_std;
                self.quarantine.clear();
                self.merges += 1;
                return GateOutcome::Merged;
            }
        }

        GateOutcome::Queued
    }

    pub fn quarantine_len(&self) -> usize {
        self.quarantine.len()
    }
}

/// The insecure comparison baseline, kept only for tests/benchmarking
/// against the gate above: updates on every single telemetry sample via
/// an exponential moving average regardless of assurance level. This
/// models what many first-generation continuous-auth products actually
/// ship, and is exactly what ALG is designed to replace.
#[derive(Debug, Clone)]
pub struct NaiveContinuousBaseline {
    pub mean: f64,
    pub std: f64,
    alpha: f64,
}

impl NaiveContinuousBaseline {
    pub fn new(initial_mean: f64, initial_std: f64) -> Self {
        Self {
            mean: initial_mean,
            std: initial_std,
            alpha: 0.02,
        }
    }

    pub fn trust_score(&self, sample: f64) -> f64 {
        if self.std <= 1e-9 {
            return if (sample - self.mean).abs() < 1e-9 {
                0.0
            } else {
                f64::INFINITY
            };
        }
        (sample - self.mean).abs() / self.std
    }

    pub fn observe(&mut self, sample: f64) {
        let err = sample - self.mean;
        self.mean += self.alpha * err;
        self.std = (1.0 - self.alpha) * self.std + self.alpha * err.abs();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_score_zero_at_mean() {
        let gate = AsymmetricLearningGate::new(180.0, 18.0);
        assert!((gate.trust_score(180.0) - 0.0).abs() < 1e-9);
    }

    #[test]
    fn trust_score_scales_with_std() {
        let gate = AsymmetricLearningGate::new(100.0, 10.0);
        assert!((gate.trust_score(120.0) - 2.0).abs() < 1e-9);
    }

    #[test]
    fn continuous_telemetry_never_mutates_baseline() {
        // trust_score is &self (read-only) -- this is a compile-time
        // guarantee as much as a runtime one, but assert the observable
        // behavior too: repeated scoring never changes mean/std.
        let gate = AsymmetricLearningGate::new(180.0, 18.0);
        let (m0, s0) = (gate.mean, gate.std);
        for i in 0..1000 {
            let _ = gate.trust_score(180.0 + i as f64);
        }
        assert_eq!(gate.mean, m0);
        assert_eq!(gate.std, s0);
    }

    #[test]
    fn single_anchor_batch_is_queued_not_merged() {
        let mut gate = AsymmetricLearningGate::new(180.0, 18.0);
        let samples = vec![181.0, 179.0, 180.0, 182.0, 178.0];
        let outcome = gate.submit_anchor_batch(&samples);
        assert_eq!(outcome, GateOutcome::Queued);
        // baseline must not have moved from a single batch
        assert_eq!(gate.mean, 180.0);
        assert_eq!(gate.merges, 0);
    }

    #[test]
    fn extreme_batch_is_rejected_outright() {
        let mut gate = AsymmetricLearningGate::new(180.0, 18.0);
        // z = |500 - 180| / 18 ~= 17.8, far above max_batch_z=3.0
        let samples = vec![500.0; 10];
        let outcome = gate.submit_anchor_batch(&samples);
        assert_eq!(outcome, GateOutcome::Rejected);
        assert_eq!(gate.mean, 180.0);
        assert_eq!(gate.rejected_batches, 1);
    }

    #[test]
    fn consistent_batches_eventually_merge() {
        let mut gate = AsymmetricLearningGate::new(180.0, 18.0);
        // Three consistent, slightly-shifted-but-agreeing batches (not a
        // monotonic drift-trend pattern: first moves up, second moves
        // down, so no monotonic sign).
        let b1 = vec![184.0, 183.0, 185.0, 184.0, 183.5];
        let b2 = vec![182.0, 181.0, 183.0, 182.5, 181.5];
        let b3 = vec![183.0, 184.0, 182.0, 183.5, 182.5];
        assert_eq!(gate.submit_anchor_batch(&b1), GateOutcome::Queued);
        assert_eq!(gate.submit_anchor_batch(&b2), GateOutcome::Queued);
        let outcome3 = gate.submit_anchor_batch(&b3);
        assert_eq!(outcome3, GateOutcome::Merged);
        assert_eq!(gate.merges, 1);
        // Baseline should have moved toward ~183, but damped by ema_alpha.
        assert!(gate.mean > 180.0 && gate.mean < 183.0);
    }

    #[test]
    fn monotonic_drift_trend_triggers_reset() {
        let mut gate = AsymmetricLearningGate::with_params(180.0, 18.0, 5, 3.0, 0.1, 0.35);
        // Monotonically increasing batch means, well beyond the tightened
        // max_drift_trend=0.1 threshold used here to make the trend
        // deterministic to trigger within required_anchor_batches.
        let batches = [181.0, 185.0, 190.0, 196.0];
        // The reset fires as soon as the monotonic trend is detectable
        // (partway through this batch sequence), after which the
        // quarantine is empty again and the next batch is merely queued
        // -- so we assert a DriftReset occurred at some point in the
        // sequence, not necessarily on the very last submission.
        let mut saw_drift_reset = false;
        for center in batches {
            let samples: Vec<f64> = (0..10).map(|i| center + (i as f64 - 4.5) * 0.1).collect();
            if gate.submit_anchor_batch(&samples) == GateOutcome::DriftReset {
                saw_drift_reset = true;
            }
        }
        assert!(saw_drift_reset, "expected a DriftReset at some point in the drift sequence");
        assert!(gate.drift_resets >= 1);
        // Baseline must not have moved despite the drift attempt.
        assert_eq!(gate.mean, 180.0);
    }

    #[test]
    fn naive_baseline_drifts_on_every_sample() {
        let mut naive = NaiveContinuousBaseline::new(180.0, 18.0);
        for _ in 0..500 {
            naive.observe(260.0); // attacker's fixed target mean
        }
        // Unlike the gate, the naive baseline should have drifted
        // substantially toward the injected value.
        assert!(naive.mean > 220.0, "naive mean should have drifted, got {}", naive.mean);
    }

    #[test]
    fn gate_resists_sustained_ambient_injection() {
        // Mirrors the Python simulation at a smaller scale: continuous
        // telemetry (even many samples) must never be passed through
        // submit_anchor_batch, and the gate's public API gives telemetry
        // no mutating path at all -- this test simply documents/asserts
        // that only trust_score (immutable) is available for that path.
        let gate = AsymmetricLearningGate::new(180.0, 18.0);
        let before = (gate.mean, gate.std);
        for _ in 0..10_000 {
            let _ = gate.trust_score(260.0);
        }
        assert_eq!((gate.mean, gate.std), before);
    }
}
