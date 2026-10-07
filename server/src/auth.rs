//! HTTP handlers for WebAuthn registration/assertion and session issuance
//! bound via DPoP (RFC 9449).
//!
//! Flow:
//! 1. `POST /api/register/start` / `/api/register/finish` -- standard
//!    (non-attested) WebAuthn passkey registration via `webauthn-rs`.
//!    We deliberately use `start_passkey_registration` rather than the
//!    `attested_passkey` flow: the attested flow requires curating a
//!    trusted manufacturer root-CA list (`attestation_ca_list`), which
//!    is unnecessary ceremony for a demo-scope deployment and would
//!    additionally reject the very common synced/Hybrid passkeys
//!    (iCloud Keychain, Google Password Manager) that most real users
//!    have. We *do* pass `ui_hint_authenticator_attachment` style intent
//!    is not available on this simpler API -- see docs/ARCHITECTURE.md
//!    for the explicit, honest trade-off this represents versus the
//!    stricter "device-bound, non-syncable" framing in the original
//!    threat model: full enforcement of non-syncability requires the
//!    attested flow + CA allow-listing and is noted there as follow-on
//!    hardening work, not a Phase 2 claim.
//! 2. `POST /api/login/start` / `/api/login/finish` -- WebAuthn
//!    assertion verification. On success this is the system's ONLY
//!    "high-assurance anchor event": it opens a short anchor window
//!    during which the very next telemetry batch for this session is
//!    permitted to flow through the Asymmetric Learning Gate's
//!    quarantine path (see `telemetry.rs`). A DPoP-bound session token
//!    is minted and returned.

use crate::state::{AppState, PendingAuth, PendingRegistration, SessionRecord};
use axum::{extract::State, http::StatusCode, Json};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use uuid::Uuid;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

#[derive(Debug, Deserialize)]
pub struct RegisterStartRequest {
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterStartResponse {
    pub registration_id: String,
    pub options: webauthn_rs::prelude::CreationChallengeResponse,
}

pub async fn register_start(
    State(state): State<AppState>,
    Json(req): Json<RegisterStartRequest>,
) -> Result<Json<RegisterStartResponse>, (StatusCode, String)> {
    if state
        .store
        .get_user_by_username(&req.username)
        .map_err(internal_err)?
        .is_some()
    {
        return Err((StatusCode::CONFLICT, "username already registered".into()));
    }

    let user_id = Uuid::new_v4();
    let (ccr, reg_state) = state
        .webauthn
        .start_passkey_registration(user_id, &req.username, &req.display_name, None)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("webauthn start failed: {e}")))?;

    let registration_id = Uuid::new_v4().to_string();
    state.pending_registrations.lock().insert(
        registration_id.clone(),
        PendingRegistration {
            user_id,
            username: req.username,
            display_name: req.display_name,
            state: reg_state,
        },
    );

    Ok(Json(RegisterStartResponse {
        registration_id,
        options: ccr,
    }))
}

#[derive(Debug, Deserialize)]
pub struct RegisterFinishRequest {
    pub registration_id: String,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Serialize)]
pub struct RegisterFinishResponse {
    pub user_id: String,
    pub username: String,
}

pub async fn register_finish(
    State(state): State<AppState>,
    Json(req): Json<RegisterFinishRequest>,
) -> Result<Json<RegisterFinishResponse>, (StatusCode, String)> {
    let pending = state
        .pending_registrations
        .lock()
        .remove(&req.registration_id)
        .ok_or((StatusCode::BAD_REQUEST, "unknown or expired registration_id".into()))?;

    let passkey = state
        .webauthn
        .finish_passkey_registration(&req.credential, &pending.state)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("webauthn finish failed: {e}")))?;

    state
        .store
        .create_user(pending.user_id, &pending.username, &pending.display_name)
        .map_err(internal_err)?;
    let cred_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(passkey.cred_id().as_slice());
    state
        .store
        .add_credential(pending.user_id, &cred_id_b64, &passkey)
        .map_err(internal_err)?;

    Ok(Json(RegisterFinishResponse {
        user_id: pending.user_id.to_string(),
        username: pending.username,
    }))
}

#[derive(Debug, Deserialize)]
pub struct LoginStartRequest {
    pub username: String,
}

#[derive(Debug, Serialize)]
pub struct LoginStartResponse {
    pub auth_id: String,
    pub options: webauthn_rs::prelude::RequestChallengeResponse,
}

pub async fn login_start(
    State(state): State<AppState>,
    Json(req): Json<LoginStartRequest>,
) -> Result<Json<LoginStartResponse>, (StatusCode, String)> {
    let user = state
        .store
        .get_user_by_username(&req.username)
        .map_err(internal_err)?
        .ok_or((StatusCode::NOT_FOUND, "unknown username".into()))?;

    let passkeys = state.store.get_passkeys(user.id).map_err(internal_err)?;
    if passkeys.is_empty() {
        return Err((StatusCode::NOT_FOUND, "no credentials registered".into()));
    }

    let (rcr, auth_state) = state
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("webauthn start failed: {e}")))?;

    let auth_id = Uuid::new_v4().to_string();
    state.pending_auths.lock().insert(
        auth_id.clone(),
        PendingAuth {
            user_id: user.id,
            username: user.username,
            state: auth_state,
        },
    );

    Ok(Json(LoginStartResponse { auth_id, options: rcr }))
}

#[derive(Debug, Deserialize)]
pub struct LoginFinishRequest {
    pub auth_id: String,
    pub credential: PublicKeyCredential,
    // Note: the DPoP proof itself is carried in the `DPoP` HTTP header of this
    // very request (not in the JSON body) -- see `dpop::verify_dpop_proof`.
}

#[derive(Debug, Serialize)]
pub struct LoginFinishResponse {
    pub session_token: String,
    pub user_id: String,
    pub username: String,
    pub anchor_window_seconds: u64,
}

/// How long after a successful WebAuthn assertion the gate will accept
/// the *next* telemetry batch as anchor-gated. Kept short and single-use
/// (consumed by the first batch that arrives) so an attacker cannot
/// indefinitely claim "this traffic followed a real authentication".
pub const ANCHOR_WINDOW: Duration = Duration::from_secs(30);

pub async fn login_finish(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    Json(req): Json<LoginFinishRequest>,
) -> Result<Json<LoginFinishResponse>, (StatusCode, String)> {
    let pending = state
        .pending_auths
        .lock()
        .remove(&req.auth_id)
        .ok_or((StatusCode::BAD_REQUEST, "unknown or expired auth_id".into()))?;

    state
        .webauthn
        .finish_passkey_authentication(&req.credential, &pending.state)
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("webauthn assertion failed: {e}")))?;

    // High-assurance anchor event confirmed. Bind the new session to the
    // caller's DPoP key, per RFC 9449 `cnf.jkt` token binding.
    let dpop_header = headers
        .get("DPoP")
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::BAD_REQUEST, "missing DPoP header".into()))?;

    let htu = request_url(&state, &uri);
    let verified = {
        let mut cache = state.replay_cache.lock();
        crate::dpop::verify_dpop_proof(dpop_header, "POST", &htu, None, &mut cache)
            .map_err(|e| (StatusCode::UNAUTHORIZED, format!("DPoP verification failed: {e}")))?
    };

    let session_token = Uuid::new_v4().to_string();
    state.sessions.lock().insert(
        session_token.clone(),
        SessionRecord {
            user_id: pending.user_id,
            username: pending.username.clone(),
            jkt: verified.jkt,
            anchor_window_expires: Some(Instant::now() + ANCHOR_WINDOW),
        },
    );

    Ok(Json(LoginFinishResponse {
        session_token,
        user_id: pending.user_id.to_string(),
        username: pending.username,
        anchor_window_seconds: ANCHOR_WINDOW.as_secs(),
    }))
}

pub fn request_url(state: &AppState, uri: &axum::http::Uri) -> String {
    format!("{}{}", state.public_base_url.trim_end_matches('/'), uri.path())
}

fn internal_err<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("internal error: {e}"))
}
