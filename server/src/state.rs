//! Shared application state threaded through all axum handlers.

use crate::alg::AsymmetricLearningGate;
use crate::detector::TrainedDetector;
use crate::dpop::ReplayCache;
use crate::store::Store;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration, Webauthn};

pub struct PendingRegistration {
    pub user_id: Uuid,
    pub username: String,
    pub display_name: String,
    pub state: PasskeyRegistration,
}

pub struct PendingAuth {
    pub user_id: Uuid,
    pub username: String,
    pub state: PasskeyAuthentication,
}

/// An authenticated, DPoP-bound session. Deliberately held only
/// in-memory (demo scope): a real deployment needs a shared session
/// store so sessions survive restarts and work across instances.
pub struct SessionRecord {
    pub user_id: Uuid,
    pub username: String,
    /// RFC 7638 thumbprint of the DPoP key this session is bound to
    /// (RFC 9449 `cnf.jkt`). Every subsequent authenticated request must
    /// present a DPoP proof whose key thumbprint matches this value.
    pub jkt: String,
    /// Set once, immediately after the WebAuthn assertion that created
    /// this session. The *next* telemetry batch (and only that one) may
    /// flow through the Asymmetric Learning Gate's anchor/quarantine
    /// path; afterward (or once expired) telemetry is read-only scoring.
    pub anchor_window_expires: Option<Instant>,
}

#[derive(Clone)]
pub struct AppState {
    pub webauthn: Arc<Webauthn>,
    pub store: Arc<Store>,
    pub pending_registrations: Arc<Mutex<HashMap<String, PendingRegistration>>>,
    pub pending_auths: Arc<Mutex<HashMap<String, PendingAuth>>>,
    pub sessions: Arc<Mutex<HashMap<String, SessionRecord>>>,
    pub replay_cache: Arc<Mutex<ReplayCache>>,
    /// Per-user, per-feature live ALG gates, loaded from / persisted to
    /// `Store` on each access. Kept in memory for the lifetime of the
    /// process between loads for low-latency telemetry scoring.
    pub gates: Arc<Mutex<HashMap<(Uuid, &'static str), AsymmetricLearningGate>>>,
    pub keystroke_detector: Arc<TrainedDetector>,
    pub mouse_detector: Arc<TrainedDetector>,
    pub public_base_url: String,
}
