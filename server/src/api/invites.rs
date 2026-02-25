use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{authenticate_device, ApiError, AppState};

/// POST /v1/invites/generate
/// Authenticated endpoint. Generate 1-10 invite codes.
/// Server stores SHA256(code), never sees plaintext after response.
#[derive(Deserialize)]
pub struct GenerateInvitesRequest {
    pub count: u32,
}

#[derive(Serialize)]
pub struct GenerateInvitesResponse {
    pub codes: Vec<String>,
}

pub async fn generate_invites(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<GenerateInvitesRequest>,
) -> Result<Json<GenerateInvitesResponse>, ApiError> {
    let device_id = authenticate_device(
        &headers,
        "POST",
        "/v1/invites/generate",
        &state.db,
        &state.redis,
    )
    .await?;

    if req.count == 0 || req.count > 10 {
        return Err(ApiError::BadRequest("count must be 1-10".into()));
    }

    let mut codes = Vec::with_capacity(req.count as usize);

    for _ in 0..req.count {
        // Generate 16 random bytes, hex-encode to 32-char code
        let mut raw = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut raw);
        let code_hex = hex::encode(raw);

        // Store SHA256(code)
        use sha2::{Digest, Sha256};
        let code_hash = Sha256::digest(code_hex.as_bytes());

        sqlx::query(
            r#"
            INSERT INTO invite_codes (code_hash, creator_device_id)
            VALUES ($1, $2)
            "#,
        )
        .bind(&code_hash[..])
        .bind(device_id)
        .execute(&state.db)
        .await?;

        codes.push(code_hex);
    }

    tracing::info!("device {} generated {} invite codes", device_id, codes.len());

    Ok(Json(GenerateInvitesResponse { codes }))
}

/// POST /v1/invites/redeem
/// Unauthenticated. Validate invite code, create account, return account_id + auth_nonce.
#[derive(Deserialize)]
pub struct RedeemInviteRequest {
    pub invite_code: String,
}

#[derive(Serialize)]
pub struct RedeemInviteResponse {
    pub account_id: Uuid,
    pub auth_nonce: String,
}

/// Minimum response time to prevent timing side-channels.
const MIN_RESPONSE_MS: u64 = 200;

pub async fn redeem_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RedeemInviteRequest>,
) -> Result<Json<RedeemInviteResponse>, ApiError> {
    let start = std::time::Instant::now();

    // Rate limit by IP
    let ip = extract_client_ip(&headers);
    check_invite_rate_limit(&state.redis, &ip).await?;

    let code = req.invite_code.trim();
    if code.is_empty() || code.len() > 64 {
        pad_response_time(start).await;
        return Err(ApiError::BadRequest("invalid invite code".into()));
    }

    // Hash the code
    use sha2::{Digest, Sha256};
    let code_hash = Sha256::digest(code.as_bytes());

    // Start explicit transaction so FOR UPDATE lock holds across all queries
    let mut tx = state.db.begin().await?;

    // Atomic: lock the invite code row, verify it's valid and unredeemed
    let invite_row: Option<(i64, Option<Uuid>)> = sqlx::query_as(
        r#"
        SELECT id, creator_device_id
        FROM invite_codes
        WHERE code_hash = $1
          AND redeemed_by IS NULL
          AND expires_at > NOW()
        FOR UPDATE SKIP LOCKED
        LIMIT 1
        "#,
    )
    .bind(&code_hash[..])
    .fetch_optional(&mut *tx)
    .await?;

    let (invite_id, creator_device_id) = match invite_row {
        Some(row) => row,
        None => {
            // Transaction drops here (implicit rollback)
            pad_response_time(start).await;
            return Err(ApiError::BadRequest("invalid or expired invite code".into()));
        }
    };

    // Look up the creator's account_id (for invited_by)
    let invited_by: Option<Uuid> = if let Some(dev_id) = creator_device_id {
        sqlx::query_as::<_, (Uuid,)>("SELECT account_id FROM devices WHERE id = $1")
            .bind(dev_id)
            .fetch_optional(&mut *tx)
            .await?
            .map(|(aid,)| aid)
    } else {
        None
    };

    // Generate auth nonce
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

    // Create account (no phone_hash needed)
    let (account_id,): (Uuid,) = sqlx::query_as(
        r#"
        INSERT INTO accounts (auth_nonce, auth_nonce_expires_at, invited_by)
        VALUES ($1, NOW() + INTERVAL '10 minutes', $2)
        RETURNING id
        "#,
    )
    .bind(&nonce[..])
    .bind(invited_by)
    .fetch_one(&mut *tx)
    .await?;

    // Mark invite as redeemed
    sqlx::query(
        r#"
        UPDATE invite_codes
        SET redeemed_by = $1
        WHERE id = $2
        "#,
    )
    .bind(account_id)
    .bind(invite_id)
    .execute(&mut *tx)
    .await?;

    // Commit the transaction
    tx.commit().await?;

    tracing::info!("invite redeemed, new account {}", account_id);

    pad_response_time(start).await;

    Ok(Json(RedeemInviteResponse {
        account_id,
        auth_nonce: hex::encode(nonce),
    }))
}

/// Rate limit: max invite redemption attempts per minute per IP.
const INVITE_RATE_LIMIT_PER_MINUTE: i64 = 10;

/// Sliding window rate limit for invite redemption via Redis sorted sets.
async fn check_invite_rate_limit(redis_client: &redis::Client, ip: &str) -> Result<(), ApiError> {
    let mut conn = match redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("redis unavailable for invite rate limit, rejecting: {}", e);
            return Err(ApiError::TooManyRequests("rate limit service unavailable".into()));
        }
    };

    let key = format!("rate:invite:{}", ip);
    let now_ms = chrono::Utc::now().timestamp_millis();
    let window_start = now_ms - 60_000;

    redis::cmd("ZREMRANGEBYSCORE")
        .arg(&key)
        .arg("-inf")
        .arg(window_start)
        .query_async::<()>(&mut conn)
        .await
        .ok();

    let count: i64 = redis::cmd("ZCARD")
        .arg(&key)
        .query_async(&mut conn)
        .await
        .unwrap_or(0);

    if count >= INVITE_RATE_LIMIT_PER_MINUTE {
        return Err(ApiError::TooManyRequests(
            "rate limit exceeded, try again later".into(),
        ));
    }

    let member = format!("{}-{:08x}", now_ms, rand::random::<u32>());
    redis::cmd("ZADD")
        .arg(&key)
        .arg(now_ms)
        .arg(&member)
        .query_async::<()>(&mut conn)
        .await
        .ok();

    redis::cmd("EXPIRE")
        .arg(&key)
        .arg(120)
        .query_async::<()>(&mut conn)
        .await
        .ok();

    Ok(())
}

/// Extract client IP — same security-hardened version as messages.rs
fn extract_client_ip(headers: &HeaderMap) -> String {
    let trusted = std::env::var("TRUSTED_PROXY_CIDRS").unwrap_or_default();
    if trusted.is_empty() {
        return "unknown".to_string();
    }
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Pad response to minimum time to prevent timing attacks.
async fn pad_response_time(start: std::time::Instant) {
    let elapsed = start.elapsed();
    let min_duration = std::time::Duration::from_millis(MIN_RESPONSE_MS);
    if elapsed < min_duration {
        tokio::time::sleep(min_duration - elapsed).await;
    }
}
