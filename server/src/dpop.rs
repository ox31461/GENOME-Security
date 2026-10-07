//! DPoP (RFC 9449) proof-of-possession verification.
//!
//! We hand-verify the DPoP JWS directly against the `p256` crate rather
//! than using `jsonwebtoken`'s JWK deserialization, because RFC 9449's
//! mandatory-to-implement algorithm is ES256 over a P-256 key supplied
//! inline in the JWT header's `jwk` member, and we need full control over
//! canonical JWK thumbprint construction (RFC 7638) for the `cnf.jkt`
//! binding anyway. This mirrors the hard requirement to use a maintained
//! crate for WebAuthn/COSE (`webauthn-rs`, see `webauthn.rs`) while being
//! honest that there is no equivalently dominant, maintained "DPoP crate"
//! in the Rust ecosystem yet — this module is a from-spec implementation
//! built on vetted primitives (`p256` for ECDSA, `sha2` for hashing).
//!
//! Scope/limitation stated plainly: only the ES256 (P-256 ECDSA)
//! algorithm is supported, matching what the browser-side SDK generates
//! via WebCrypto's `ECDSA` with curve `P-256`. RFC 9449 permits other
//! algorithms; a production deployment serving non-browser clients may
//! need to add RSA/EdDSA support.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DpopError {
    #[error("malformed DPoP proof: {0}")]
    Malformed(String),
    #[error("unsupported DPoP algorithm (only ES256/P-256 is supported)")]
    UnsupportedAlgorithm,
    #[error("DPoP proof signature verification failed")]
    BadSignature,
    #[error("DPoP proof `iat` is outside the acceptable freshness window")]
    StaleOrFutureIat,
    #[error("DPoP proof `jti` has already been used (replay rejected)")]
    ReplayedJti,
    #[error("DPoP proof `htm` does not match the request method")]
    MethodMismatch,
    #[error("DPoP proof `htu` does not match the request URL")]
    UrlMismatch,
    #[error("DPoP proof `ath` does not match the bound access token")]
    AccessTokenHashMismatch,
}

#[derive(Debug, Deserialize)]
struct DpopHeader {
    typ: String,
    alg: String,
    jwk: EcJwk,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EcJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

#[derive(Debug, Deserialize)]
struct DpopClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: i64,
    ath: Option<String>,
}

/// Result of a successfully verified DPoP proof.
#[derive(Debug, Clone)]
pub struct DpopVerified {
    /// RFC 7638 JWK thumbprint of the proof's public key, used as the
    /// `cnf.jkt` confirmation value binding issued tokens to this key.
    pub jkt: String,
    pub jti: String,
    pub iat: i64,
}

/// Max allowed clock skew (seconds) between the proof's `iat` and the
/// server's current time, in either direction.
const MAX_IAT_SKEW_SECS: i64 = 60;

/// In-memory replay cache for `jti` values, keyed by jti with an
/// expiry timestamp. A real multi-instance deployment needs a shared
/// store (e.g. Redis) instead; documented as a demo-scope limitation in
/// `server/README.md`.
#[derive(Default)]
pub struct ReplayCache {
    seen: HashMap<String, i64>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if `jti` was already seen (and thus is a replay).
    /// Otherwise records it with an expiry and returns false.
    pub fn check_and_insert(&mut self, jti: &str, now: i64) -> bool {
        self.cleanup(now);
        if self.seen.contains_key(jti) {
            true
        } else {
            self.seen.insert(jti.to_string(), now + MAX_IAT_SKEW_SECS * 2);
            false
        }
    }

    fn cleanup(&mut self, now: i64) {
        self.seen.retain(|_, expiry| *expiry > now);
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Compute the RFC 7638 JWK thumbprint for an EC P-256 public key: the
/// base64url (no padding) SHA-256 digest of the canonical JSON object
/// `{"crv":...,"kty":...,"x":...,"y":...}` with members in that exact
/// lexicographic order and no insignificant whitespace.
pub fn jwk_thumbprint(jwk: &EcJwk) -> String {
    let canonical = format!(
        "{{\"crv\":\"{}\",\"kty\":\"{}\",\"x\":\"{}\",\"y\":\"{}\"}}",
        jwk.crv, jwk.kty, jwk.x, jwk.y
    );
    let digest = Sha256::digest(canonical.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// Verify a DPoP proof JWT against the expected HTTP method/URL, and
/// (if `expected_access_token` is provided) the bound access token's
/// hash. Returns the verified proof's key thumbprint and claims on
/// success.
pub fn verify_dpop_proof(
    proof_jwt: &str,
    expected_htm: &str,
    expected_htu: &str,
    expected_access_token: Option<&str>,
    replay_cache: &mut ReplayCache,
) -> Result<DpopVerified, DpopError> {
    let parts: Vec<&str> = proof_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(DpopError::Malformed("expected 3 dot-separated JWS segments".into()));
    }
    let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|e| DpopError::Malformed(format!("bad header base64: {e}")))?;
    let header: DpopHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| DpopError::Malformed(format!("bad header json: {e}")))?;

    if header.typ != "dpop+jwt" {
        return Err(DpopError::Malformed(format!(
            "expected typ=dpop+jwt, got {}",
            header.typ
        )));
    }
    if header.alg != "ES256" || header.jwk.kty != "EC" || header.jwk.crv != "P-256" {
        return Err(DpopError::UnsupportedAlgorithm);
    }

    // Reconstruct the uncompressed SEC1 point (0x04 || x || y) and the
    // verifying key.
    let x = URL_SAFE_NO_PAD
        .decode(&header.jwk.x)
        .map_err(|e| DpopError::Malformed(format!("bad jwk.x: {e}")))?;
    let y = URL_SAFE_NO_PAD
        .decode(&header.jwk.y)
        .map_err(|e| DpopError::Malformed(format!("bad jwk.y: {e}")))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(DpopError::Malformed("jwk.x/jwk.y must be 32 bytes for P-256".into()));
    }
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    let verifying_key =
        VerifyingKey::from_sec1_bytes(&point).map_err(|_| DpopError::Malformed("invalid EC point".into()))?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| DpopError::Malformed(format!("bad signature base64: {e}")))?;
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|_| DpopError::Malformed("invalid signature bytes".into()))?;

    let signing_input = format!("{header_b64}.{payload_b64}");
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| DpopError::BadSignature)?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| DpopError::Malformed(format!("bad payload base64: {e}")))?;
    let claims: DpopClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| DpopError::Malformed(format!("bad payload json: {e}")))?;

    let now = now_unix();
    if (now - claims.iat).abs() > MAX_IAT_SKEW_SECS {
        return Err(DpopError::StaleOrFutureIat);
    }

    if replay_cache.check_and_insert(&claims.jti, now) {
        return Err(DpopError::ReplayedJti);
    }

    if !claims.htm.eq_ignore_ascii_case(expected_htm) {
        return Err(DpopError::MethodMismatch);
    }

    if !htu_matches(&claims.htu, expected_htu) {
        return Err(DpopError::UrlMismatch);
    }

    if let Some(token) = expected_access_token {
        let expected_ath = URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()));
        match &claims.ath {
            Some(ath) if ath == &expected_ath => {}
            _ => return Err(DpopError::AccessTokenHashMismatch),
        }
    }

    Ok(DpopVerified {
        jkt: jwk_thumbprint(&header.jwk),
        jti: claims.jti,
        iat: claims.iat,
    })
}

/// Compare `htu` (from the proof) against the expected request URL,
/// ignoring query string and fragment per RFC 9449 section 4.2, which
/// specifies `htu` must match the request URL without query/fragment.
fn htu_matches(claimed: &str, expected: &str) -> bool {
    fn normalize(u: &str) -> Option<String> {
        let parsed = url::Url::parse(u).ok()?;
        Some(format!(
            "{}://{}{}",
            parsed.scheme(),
            parsed.host_str().unwrap_or(""),
            parsed.path()
        ))
    }
    match (normalize(claimed), normalize(expected)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use rand::rngs::OsRng;

    fn make_proof(htm: &str, htu: &str, jti: &str, iat: i64, ath: Option<&str>) -> (String, EcJwk) {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
        let jwk = EcJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x,
            y,
        };

        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": jwk,
        });
        let mut claims = serde_json::json!({
            "jti": jti,
            "htm": htm,
            "htu": htu,
            "iat": iat,
        });
        if let Some(a) = ath {
            claims["ath"] = serde_json::Value::String(a.to_string());
        }

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature: Signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        (format!("{header_b64}.{payload_b64}.{sig_b64}"), jwk)
    }

    #[test]
    fn valid_proof_verifies_and_yields_thumbprint() {
        let now = now_unix();
        let (proof, jwk) = make_proof("POST", "https://example.com/api/login", "jti-1", now, None);
        let mut cache = ReplayCache::new();
        let result = verify_dpop_proof(&proof, "POST", "https://example.com/api/login", None, &mut cache).unwrap();
        assert_eq!(result.jkt, jwk_thumbprint(&jwk));
        assert_eq!(result.jti, "jti-1");
    }

    #[test]
    fn replayed_jti_is_rejected() {
        let now = now_unix();
        let (proof, _jwk) = make_proof("POST", "https://example.com/api/login", "jti-replay", now, None);
        let mut cache = ReplayCache::new();
        assert!(verify_dpop_proof(&proof, "POST", "https://example.com/api/login", None, &mut cache).is_ok());
        let err = verify_dpop_proof(&proof, "POST", "https://example.com/api/login", None, &mut cache).unwrap_err();
        assert!(matches!(err, DpopError::ReplayedJti));
    }

    #[test]
    fn stale_iat_is_rejected() {
        let old = now_unix() - 3600;
        let (proof, _jwk) = make_proof("POST", "https://example.com/api/login", "jti-old", old, None);
        let mut cache = ReplayCache::new();
        let err = verify_dpop_proof(&proof, "POST", "https://example.com/api/login", None, &mut cache).unwrap_err();
        assert!(matches!(err, DpopError::StaleOrFutureIat));
    }

    #[test]
    fn method_mismatch_is_rejected() {
        let now = now_unix();
        let (proof, _jwk) = make_proof("POST", "https://example.com/api/login", "jti-m", now, None);
        let mut cache = ReplayCache::new();
        let err = verify_dpop_proof(&proof, "GET", "https://example.com/api/login", None, &mut cache).unwrap_err();
        assert!(matches!(err, DpopError::MethodMismatch));
    }

    #[test]
    fn url_mismatch_is_rejected() {
        let now = now_unix();
        let (proof, _jwk) = make_proof("POST", "https://example.com/api/login", "jti-u", now, None);
        let mut cache = ReplayCache::new();
        let err =
            verify_dpop_proof(&proof, "POST", "https://example.com/api/other", None, &mut cache).unwrap_err();
        assert!(matches!(err, DpopError::UrlMismatch));
    }

    #[test]
    fn query_string_is_ignored_in_htu_comparison() {
        let now = now_unix();
        let (proof, _jwk) = make_proof("GET", "https://example.com/api/telemetry?x=1", "jti-q", now, None);
        let mut cache = ReplayCache::new();
        assert!(verify_dpop_proof(&proof, "GET", "https://example.com/api/telemetry", None, &mut cache).is_ok());
    }

    #[test]
    fn access_token_hash_binding_is_enforced() {
        let now = now_unix();
        let token = "opaque-session-token-abc123";
        let ath = URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()));
        let (proof, _jwk) =
            make_proof("GET", "https://example.com/api/telemetry", "jti-ath", now, Some(&ath));
        let mut cache = ReplayCache::new();
        assert!(verify_dpop_proof(
            &proof,
            "GET",
            "https://example.com/api/telemetry",
            Some(token),
            &mut cache
        )
        .is_ok());

        let (proof2, _jwk2) =
            make_proof("GET", "https://example.com/api/telemetry", "jti-ath-2", now, Some("wrong-hash"));
        let err = verify_dpop_proof(
            &proof2,
            "GET",
            "https://example.com/api/telemetry",
            Some(token),
            &mut cache,
        )
        .unwrap_err();
        assert!(matches!(err, DpopError::AccessTokenHashMismatch));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let now = now_unix();
        let (mut proof, _jwk) = make_proof("POST", "https://example.com/api/login", "jti-t", now, None);
        // Flip a character near the end (inside the signature segment).
        let len = proof.len();
        let last_char = proof.chars().last().unwrap();
        let replacement = if last_char == 'A' { 'B' } else { 'A' };
        proof.replace_range(len - 1..len, &replacement.to_string());
        let mut cache = ReplayCache::new();
        let err = verify_dpop_proof(&proof, "POST", "https://example.com/api/login", None, &mut cache).unwrap_err();
        assert!(matches!(err, DpopError::BadSignature));
    }
}
