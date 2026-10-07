//! SQLite-backed persistence for durable entities (users, WebAuthn
//! credentials, per-user Asymmetric Learning Gate state).
//!
//! Scope note (demo-honesty, carried over from Phase 1's discipline of
//! not overclaiming): this is a single-file SQLite database behind a
//! `Mutex`, adequate for a single-instance demo deployment. A real
//! production deployment needs a proper multi-instance-safe datastore
//! (e.g. Postgres) plus a shared replay-cache/session store (e.g.
//! Redis) for the ephemeral WebAuthn ceremony state and DPoP replay
//! cache that this demo keeps in-memory (see `AppState` in `main.rs`).

use crate::alg::AsymmetricLearningGate;
use rusqlite::{params, Connection, OptionalExtension};
use std::sync::Mutex;
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

pub struct Store {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
pub struct UserRecord {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
}

impl Store {
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                display_name TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS credentials (
                credential_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id),
                passkey_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS baselines (
                user_id TEXT NOT NULL,
                feature TEXT NOT NULL,
                gate_json TEXT NOT NULL,
                PRIMARY KEY (user_id, feature)
            );
            ",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn create_user(&self, id: Uuid, username: &str, display_name: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO users (id, username, display_name) VALUES (?1, ?2, ?3)",
            params![id.to_string(), username, display_name],
        )?;
        Ok(())
    }

    pub fn get_user_by_username(&self, username: &str) -> rusqlite::Result<Option<UserRecord>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, username, display_name FROM users WHERE username = ?1",
            params![username],
            |row| {
                let id_str: String = row.get(0)?;
                Ok(UserRecord {
                    id: Uuid::parse_str(&id_str).unwrap(),
                    username: row.get(1)?,
                    display_name: row.get(2)?,
                })
            },
        )
        .optional()
    }

    pub fn add_credential(&self, user_id: Uuid, credential_id: &str, passkey: &Passkey) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        let json = serde_json::to_string(passkey).expect("Passkey must serialize");
        conn.execute(
            "INSERT OR REPLACE INTO credentials (credential_id, user_id, passkey_json) VALUES (?1, ?2, ?3)",
            params![credential_id, user_id.to_string(), json],
        )?;
        Ok(())
    }

    pub fn get_passkeys(&self, user_id: Uuid) -> rusqlite::Result<Vec<Passkey>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT passkey_json FROM credentials WHERE user_id = ?1")?;
        let rows = stmt.query_map(params![user_id.to_string()], |row| {
            let json: String = row.get(0)?;
            Ok(json)
        })?;
        let mut out = Vec::new();
        for row in rows {
            let json = row?;
            out.push(serde_json::from_str(&json).expect("stored Passkey must deserialize"));
        }
        Ok(out)
    }

    /// Load the persisted ALG state for (user, feature), or construct a
    /// fresh one seeded from `default_mean`/`default_std` on first use
    /// (modeling an enrollment-time baseline).
    pub fn load_or_init_gate(
        &self,
        user_id: Uuid,
        feature: &str,
        default_mean: f64,
        default_std: f64,
    ) -> rusqlite::Result<AsymmetricLearningGate> {
        let conn = self.conn.lock().unwrap();
        let existing: Option<String> = conn
            .query_row(
                "SELECT gate_json FROM baselines WHERE user_id = ?1 AND feature = ?2",
                params![user_id.to_string(), feature],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(json) => Ok(serde_json::from_str(&json).expect("stored gate must deserialize")),
            None => Ok(AsymmetricLearningGate::new(default_mean, default_std)),
        }
    }

    pub fn save_gate(&self, user_id: Uuid, feature: &str, gate: &AsymmetricLearningGate) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        let json = serde_json::to_string(gate).expect("gate must serialize");
        conn.execute(
            "INSERT INTO baselines (user_id, feature, gate_json) VALUES (?1, ?2, ?3)
             ON CONFLICT(user_id, feature) DO UPDATE SET gate_json = excluded.gate_json",
            params![user_id.to_string(), feature, json],
        )?;
        Ok(())
    }
}
