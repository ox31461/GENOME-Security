//! Telemetry ingestion endpoint: accepts a batch of keystroke or mouse
//! timing samples from an authenticated session, runs them through the
//! synthetic-input detector and the Asymmetric Learning Gate, and
//! returns a combined trust score + CARTA-style decision.
//!
//! Decision policy (documented here plainly as a demo-scope starting
//! point, NOT an empirically validated fraud-risk model -- see
//! docs/THREAT_MODEL.md for the full CARTA tier discussion):
//!
//!   risk = 0.6 * min(baseline_z / 5.0, 1.0) + 0.4 * synthetic_probability
//!
//!   risk <  0.30                => Allow
//!   0.30 <= risk < 0.60          => StepUp  (require a fresh WebAuthn
//!                                   assertion; a successful one opens
//!                                   a new anchor window)
//!   risk >= 0.60                => Deny     (terminate the session)
//!
//! The weighting (0.6 behavioral / 0.4 synthetic-input) and the tier
//! cut points are reasonable starting defaults, not numbers derived
//! from a production fraud dataset -- tuning these against real traffic
//! is explicitly called out as Phase 3+ work in docs/PHASE_PLAN.md.

use crate::detector::InputKind;
use crate::state::AppState;
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TelemetryKind {
    Keystroke,
    Mouse,
}

#[derive(Debug, Deserialize)]
pub struct TelemetryRequest {
    pub session_token: String,
    pub kind: TelemetryKind,
    /// Raw inter-event timing samples in milliseconds (keystroke dwell
    /// or flight times; mouse inter-sample deltas). Needs at least 8
    /// samples for the spectral/entropy features to be meaningful.
    pub samples: Vec<f64>,
}

#[derive(Debug, Serialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    StepUp,
    Deny,
}

#[derive(Debug, Serialize)]
pub struct TelemetryResponse {
    pub trust_score: f64,
    pub risk: f64,
    pub decision: Decision,
    pub synthetic_probability: f64,
    pub baseline_z: f64,
    pub gate_outcome: Option<String>,
}

const MIN_SAMPLES: usize = 8;

pub async fn ingest(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    Json(req): Json<TelemetryRequest>,
) -> Result<Json<TelemetryResponse>, (StatusCode, String)> {
    if req.samples.len() < MIN_SAMPLES {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("need at least {MIN_SAMPLES} samples, got {}", req.samples.len()),
        ));
    }

    // --- Session + DPoP binding check -------------------------------
    let dpop_header = headers
        .get("DPoP")
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::BAD_REQUEST, "missing DPoP header".into()))?;

    let (user_id, username, jkt, anchor_eligible) = {
        let mut sessions = state.sessions.lock();
        let session = sessions
            .get_mut(&req.session_token)
            .ok_or((StatusCode::UNAUTHORIZED, "unknown or expired session".into()))?;

        let anchor_eligible = session
            .anchor_window_expires
            .map(|deadline| Instant::now() < deadline)
            .unwrap_or(false);
        // Single-use: whether or not this batch ends up anchor-gated,
        // the window is consumed by the first telemetry batch to arrive.
        session.anchor_window_expires = None;

        (session.user_id, session.username.clone(), session.jkt.clone(), anchor_eligible)
    };

    let htu = crate::auth::request_url(&state, &uri);
    let verified = {
        let mut cache = state.replay_cache.lock();
        crate::dpop::verify_dpop_proof(
            dpop_header,
            "POST",
            &htu,
            Some(req.session_token.as_str()),
            &mut cache,
        )
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("DPoP verification failed: {e}")))?
    };
    if verified.jkt != jkt {
        return Err((
            StatusCode::UNAUTHORIZED,
            "DPoP proof key does not match the key this session is bound to".into(),
        ));
    }

    // --- Synthetic-input detection -----------------------------------
    let (input_kind, detector) = match req.kind {
        TelemetryKind::Keystroke => (InputKind::Keystroke, &state.keystroke_detector),
        TelemetryKind::Mouse => (InputKind::Mouse, &state.mouse_detector),
    };
    let features = crate::detector::extract_features(&req.samples, input_kind);
    let synthetic_probability = detector.classifier.predict_proba(&features);

    // --- Asymmetric Learning Gate (behavioral baseline) --------------
    let feature_key: &'static str = match req.kind {
        TelemetryKind::Keystroke => "keystroke_interval_ms",
        TelemetryKind::Mouse => "mouse_sample_delta_ms",
    };
    let batch_mean = req.samples.iter().sum::<f64>() / req.samples.len() as f64;

    let mut gates = state.gates.lock();
    let gate = gates.entry((user_id, feature_key)).or_insert_with(|| {
        state
            .store
            .load_or_init_gate(user_id, feature_key, batch_mean, batch_mean.max(1.0) * 0.1)
            .expect("store load_or_init_gate failed")
    });

    let baseline_z = gate.trust_score(batch_mean);
    let gate_outcome = if anchor_eligible {
        let outcome = gate.submit_anchor_batch(&req.samples);
        state
            .store
            .save_gate(user_id, feature_key, gate)
            .expect("store save_gate failed");
        Some(format!("{outcome:?}"))
    } else {
        None
    };

    // --- Combine into a risk score + CARTA-style decision ------------
    let normalized_z = (baseline_z / 5.0).min(1.0);
    let risk = 0.6 * normalized_z + 0.4 * synthetic_probability;
    let decision = if risk >= 0.60 {
        Decision::Deny
    } else if risk >= 0.30 {
        Decision::StepUp
    } else {
        Decision::Allow
    };
    let trust_score = ((1.0 - risk) * 100.0).clamp(0.0, 100.0);

    tracing::info!(
        user = %username,
        kind = ?req.kind,
        synthetic_probability,
        baseline_z,
        risk,
        decision = ?decision,
        gate_outcome = ?gate_outcome,
        "telemetry scored"
    );

    Ok(Json(TelemetryResponse {
        trust_score,
        risk,
        decision,
        synthetic_probability,
        baseline_z,
        gate_outcome,
    }))
}
