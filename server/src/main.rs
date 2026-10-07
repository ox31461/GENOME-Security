//! GENOME Security Phase 2 risk engine server.
//!
//! Wires together:
//!   - WebAuthn (FIDO2 passkey) registration/assertion (`webauthn-rs`)
//!   - DPoP (RFC 9449) proof-of-possession session binding (`dpop.rs`)
//!   - The Asymmetric Learning Gate behavioral baseline (`alg.rs`)
//!   - The synthetic-input injection detector (`detector.rs`)
//!   - A telemetry ingestion endpoint combining the two into a
//!     CARTA-style trust score + decision (`telemetry.rs`)
//!
//! Storage: SQLite (via `store.rs`) for durable entities (users,
//! WebAuthn credentials, ALG baselines); in-memory maps for ephemeral
//! ceremony state (pending registrations/authentications, sessions,
//! DPoP replay cache). See `server/README.md` for why this is fine for
//! a demo but not for a multi-instance production deployment.

mod alg;
mod auth;
mod detector;
mod dpop;
mod dsp;
mod state;
mod store;
mod synthetic_input;
mod telemetry;

use axum::{
    routing::{get, post},
    Router,
};
use parking_lot::Mutex;
use state::AppState;
use std::collections::HashMap;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use webauthn_rs::prelude::{Url, WebauthnBuilder};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,genome_risk_engine=debug")),
        )
        .init();

    let rp_id = std::env::var("GENOME_RP_ID").unwrap_or_else(|_| "localhost".to_string());
    let public_base_url =
        std::env::var("GENOME_PUBLIC_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let rp_origin = Url::parse(&public_base_url).expect("GENOME_PUBLIC_URL must be a valid URL");

    let webauthn = WebauthnBuilder::new(&rp_id, &rp_origin)
        .expect("invalid WebAuthn rp_id/origin configuration")
        .rp_name("GENOME Security Demo")
        .build()
        .expect("failed to build Webauthn instance");

    let db_path = std::env::var("GENOME_DB_PATH").unwrap_or_else(|_| "genome.sqlite3".to_string());
    let store = store::Store::open(&db_path).expect("failed to open SQLite store");

    tracing::info!("Training synthetic-input detectors at startup (real, currently-measured numbers)...");
    let keystroke_detector = detector::train_and_evaluate(detector::InputKind::Keystroke, 150, 128, 7);
    tracing::info!(
        "Keystroke detector: holdout accuracy={:.3} AUC={:.3}",
        keystroke_detector.holdout_accuracy,
        keystroke_detector.holdout_auc
    );
    let mouse_detector = detector::train_and_evaluate(detector::InputKind::Mouse, 150, 128, 11);
    tracing::info!(
        "Mouse detector: holdout accuracy={:.3} AUC={:.3}",
        mouse_detector.holdout_accuracy,
        mouse_detector.holdout_auc
    );

    let app_state = AppState {
        webauthn: Arc::new(webauthn),
        store: Arc::new(store),
        pending_registrations: Arc::new(Mutex::new(HashMap::new())),
        pending_auths: Arc::new(Mutex::new(HashMap::new())),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        replay_cache: Arc::new(Mutex::new(dpop::ReplayCache::new())),
        gates: Arc::new(Mutex::new(HashMap::new())),
        keystroke_detector: Arc::new(keystroke_detector),
        mouse_detector: Arc::new(mouse_detector),
        public_base_url,
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/register/start", post(auth::register_start))
        .route("/api/register/finish", post(auth::register_finish))
        .route("/api/login/start", post(auth::login_start))
        .route("/api/login/finish", post(auth::login_finish))
        .route("/api/telemetry", post(telemetry::ingest))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    let bind_addr = std::env::var("GENOME_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    tracing::info!("GENOME Security risk engine listening on http://{bind_addr}");
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("failed to bind listener");
    axum::serve(listener, app).await.expect("server error");
}

async fn health() -> &'static str {
    "ok"
}
