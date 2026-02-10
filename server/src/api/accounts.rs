use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{ApiError, AppState};

/// POST /v1/register
/// Client sends a phone hash. Server creates an account if new.
/// Response shape is IDENTICAL for new and existing accounts (AV-11: anti-enumeration).
/// New account: real account_id + valid auth_nonce.
/// Existing account: random account_id + random (unusable) auth_nonce.
#[derive(Deserialize)]
pub struct RegisterRequest {
    /// SHA256(phone || client_salt) - 32 bytes, hex-encoded
    pub phone_hash: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub account_id: Uuid,
    /// One-time nonce for authorizing key upload (hex, consumed after use)
    pub auth_nonce: String,
}

/// Minimum response time to prevent timing side-channels.
const MIN_RESPONSE_MS: u64 = 200;

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, ApiError> {
    let start = std::time::Instant::now();

    let phone_hash = hex::decode(&req.phone_hash)
        .map_err(|_| ApiError::BadRequest("phone_hash must be valid hex".into()))?;

    if phone_hash.len() != 32 {
        return Err(ApiError::BadRequest("phone_hash must be 32 bytes".into()));
    }

    // Always generate a nonce (constant-cost regardless of account existence)
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

    // INSERT ... ON CONFLICT DO NOTHING — both paths hit the DB (AV-11)
    let result: Option<(Uuid,)> = sqlx::query_as(
        r#"
        INSERT INTO accounts (phone_hash, auth_nonce, auth_nonce_expires_at)
        VALUES ($1, $2, NOW() + INTERVAL '10 minutes')
        ON CONFLICT (phone_hash) DO NOTHING
        RETURNING id
        "#
    )
    .bind(&phone_hash)
    .bind(&nonce[..])
    .fetch_optional(&state.db)
    .await?;

    let (account_id, auth_nonce_hex) = match result {
        Some((id,)) => {
            tracing::info!("registered account {}", id);
            (id, hex::encode(nonce))
        }
        None => {
            // Existing account: return indistinguishable response with random values
            (Uuid::new_v4(), hex::encode(nonce))
        }
    };

    // Timing normalization: pad to minimum response time (AV-11)
    let elapsed = start.elapsed();
    let min_duration = std::time::Duration::from_millis(MIN_RESPONSE_MS);
    if elapsed < min_duration {
        tokio::time::sleep(min_duration - elapsed).await;
    }

    Ok(Json(RegisterResponse {
        account_id,
        auth_nonce: auth_nonce_hex,
    }))
}

/// POST /v1/verify
/// POC: no-op verification. In production, this would check an SMS code.
#[derive(Deserialize)]
pub struct VerifyRequest {
    pub phone_hash: String,
    pub code: String,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub verified: bool,
}

pub async fn verify(
    State(_state): State<AppState>,
    Json(_req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    // POC: always succeed
    Ok(Json(VerifyResponse { verified: true }))
}
