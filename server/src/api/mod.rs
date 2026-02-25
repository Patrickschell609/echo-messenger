pub mod accounts;
pub mod groups;
pub mod invites;
pub mod keys;
pub mod messages;
pub mod profiles;

use std::collections::HashMap;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use sqlx::PgPool;
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

use crate::config::ServerConfig;
use crate::config::transparency::TransparencySigningKey;

/// Outbound WebSocket message types.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub enum WsOutbound {
    NewMessage {
        id: i64,
        envelope: String,
        queued_at: i64,
    },
    Typing {
        sender_device_id: Uuid,
    },
    Delivered {
        sender_device_id: Uuid,
        up_to_timestamp: i64,
    },
    Read {
        sender_device_id: Uuid,
        up_to_timestamp: i64,
    },
    Ping,
}

/// Shared application state passed to all handlers via Axum's State extractor.
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub redis: redis::Client,
    pub config: ServerConfig,
    pub transparency_key: TransparencySigningKey,
    pub ws_connections: Arc<RwLock<HashMap<Uuid, mpsc::Sender<WsOutbound>>>>,
}

/// Unified error type for API responses.
#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    NotFound(String),
    Unauthorized,
    PayloadTooLarge(String),
    TooManyRequests(String),
    Internal(String),
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".into()),
            ApiError::PayloadTooLarge(msg) => (StatusCode::PAYLOAD_TOO_LARGE, msg),
            ApiError::TooManyRequests(msg) => (StatusCode::TOO_MANY_REQUESTS, msg),
            ApiError::Internal(msg) => {
                tracing::error!("internal error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
            }
        };
        (status, Json(ErrorBody { error: message })).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        ApiError::Internal(e.to_string())
    }
}

/// Timestamp tolerance for Ed25519 auth signatures: +/- 2 minutes (tightened from 5).
const AUTH_TIMESTAMP_TOLERANCE_SECS: u64 = 120;

/// Authenticate a device via Ed25519 signed request headers.
///
/// Client sends:
///   X-Device-ID: <uuid>
///   X-Auth-Timestamp: <unix_secs>
///   X-Auth-Nonce: <hex(16 random bytes)> — prevents replay attacks
///   X-Auth-Signature: <hex(Ed25519.sign(priv, device_id || timestamp || nonce || method || path || body_hash))>
///
/// Server: lookup device's identity_key from DB, verify signature, check timestamp,
/// reject seen nonces within the timestamp window.
pub async fn authenticate_device(
    headers: &axum::http::HeaderMap,
    method: &str,
    path: &str,
    db: &PgPool,
    redis: &redis::Client,
) -> Result<uuid::Uuid, ApiError> {
    let device_id_str = headers
        .get("x-device-id")
        .ok_or(ApiError::Unauthorized)?
        .to_str()
        .map_err(|_| ApiError::BadRequest("invalid device id header".into()))?;

    let device_id = uuid::Uuid::parse_str(device_id_str)
        .map_err(|_| ApiError::BadRequest("invalid device id".into()))?;

    let timestamp_str = headers
        .get("x-auth-timestamp")
        .ok_or(ApiError::Unauthorized)?
        .to_str()
        .map_err(|_| ApiError::BadRequest("invalid timestamp header".into()))?;

    let timestamp: u64 = timestamp_str
        .parse()
        .map_err(|_| ApiError::BadRequest("invalid timestamp".into()))?;

    // Require nonce header for replay protection
    let nonce_hex = headers
        .get("x-auth-nonce")
        .ok_or(ApiError::Unauthorized)?
        .to_str()
        .map_err(|_| ApiError::BadRequest("invalid nonce header".into()))?;

    if hex::decode(nonce_hex).map_or(true, |b| b.len() != 16) {
        return Err(ApiError::BadRequest("nonce must be 32 hex chars (16 bytes)".into()));
    }

    let sig_hex = headers
        .get("x-auth-signature")
        .ok_or(ApiError::Unauthorized)?
        .to_str()
        .map_err(|_| ApiError::BadRequest("invalid signature header".into()))?;

    let sig_bytes = hex::decode(sig_hex)
        .map_err(|_| ApiError::BadRequest("invalid signature hex".into()))?;

    if sig_bytes.len() != 64 {
        return Err(ApiError::BadRequest("signature must be 64 bytes".into()));
    }

    // Check timestamp freshness
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let diff = if now > timestamp { now - timestamp } else { timestamp - now };
    if diff > AUTH_TIMESTAMP_TOLERANCE_SECS {
        return Err(ApiError::Unauthorized);
    }

    // Check nonce uniqueness (reject replays within timestamp window)
    let nonce_key = format!("auth:nonce:{}", nonce_hex);
    match redis.get_multiplexed_async_connection().await {
        Ok(mut conn) => {
            let was_set: bool = redis::cmd("SET")
                .arg(&nonce_key)
                .arg("1")
                .arg("NX")                       // only set if not exists
                .arg("EX")
                .arg(AUTH_TIMESTAMP_TOLERANCE_SECS * 2) // TTL = 2x window
                .query_async(&mut conn)
                .await
                .unwrap_or(false);
            if !was_set {
                return Err(ApiError::Unauthorized); // nonce already seen = replay
            }
        }
        Err(e) => {
            // Fail closed — if Redis is down, reject auth (don't allow replay)
            tracing::error!("redis unavailable for nonce check, rejecting: {}", e);
            return Err(ApiError::Internal("auth service unavailable".into()));
        }
    }

    // Look up the device's identity_key (Ed25519 public key) from DB
    let row: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT identity_key FROM devices WHERE id = $1"
    )
    .bind(device_id)
    .fetch_optional(db)
    .await?;

    let (identity_key_bytes,) = row.ok_or(ApiError::Unauthorized)?;

    if identity_key_bytes.len() != 32 {
        return Err(ApiError::Internal("stored identity_key wrong size".into()));
    }

    // Build the signed message: device_id || timestamp || nonce || method || path || body_hash
    // body_hash is SHA-256 of the request body (empty hash for GET)
    let body_hash_hex = headers
        .get("x-auth-body-hash")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"); // SHA-256 of empty

    let mut message = Vec::new();
    message.extend_from_slice(device_id_str.as_bytes());
    message.extend_from_slice(timestamp_str.as_bytes());
    message.extend_from_slice(nonce_hex.as_bytes());
    message.extend_from_slice(method.as_bytes());
    message.extend_from_slice(path.as_bytes());
    message.extend_from_slice(body_hash_hex.as_bytes());

    // Verify Ed25519 signature
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(&identity_key_bytes);
    let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| ApiError::Internal("invalid stored public key".into()))?;

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key
        .verify(&message, &signature)
        .map_err(|_| ApiError::Unauthorized)?;

    Ok(device_id)
}

