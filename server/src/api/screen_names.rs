use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};

use super::{authenticate_device, ApiError, AppState};

/// Rate limit: max screen name checks per minute per IP (unauthenticated).
const CHECK_RATE_LIMIT_PER_MINUTE: i64 = 20;

/// Reserved names that cannot be claimed.
const RESERVED_NAMES: &[&str] = &[
    "admin", "echo", "system", "support", "mod", "moderator", "help",
    "null", "undefined", "root", "server", "bot", "ghost_protocol",
    "official", "staff", "team", "security", "test", "anonymous",
];

/// Early adopter threshold: first 100 users get 3-char minimum.
const EARLY_ADOPTER_LIMIT: i64 = 100;

/// Validate a screen name against format and policy rules.
fn validate_screen_name(name: &str, min_len: usize) -> Result<(), ApiError> {
    if name.len() < min_len {
        return Err(ApiError::BadRequest(format!(
            "Screen name must be at least {} characters", min_len
        )));
    }
    if name.len() > 20 {
        return Err(ApiError::BadRequest("Screen name max 20 characters".into()));
    }

    let chars: Vec<char> = name.chars().collect();

    // Must start with a letter
    if !chars[0].is_ascii_alphabetic() {
        return Err(ApiError::BadRequest("Screen name must start with a letter".into()));
    }

    // Must end with alphanumeric
    if !chars.last().unwrap().is_ascii_alphanumeric() {
        return Err(ApiError::BadRequest("Screen name must end with a letter or number".into()));
    }

    // Only allow [a-zA-Z0-9_.]
    for c in &chars {
        if !c.is_ascii_alphanumeric() && *c != '_' && *c != '.' {
            return Err(ApiError::BadRequest(
                "Screen name can only contain letters, numbers, underscores, and dots".into(),
            ));
        }
    }

    // No consecutive special characters
    for w in chars.windows(2) {
        let a_special = w[0] == '_' || w[0] == '.';
        let b_special = w[1] == '_' || w[1] == '.';
        if a_special && b_special {
            return Err(ApiError::BadRequest(
                "Screen name cannot have consecutive dots or underscores".into(),
            ));
        }
    }

    // Reserved names
    if RESERVED_NAMES.contains(&name.to_lowercase().as_str()) {
        return Err(ApiError::BadRequest("That screen name is reserved".into()));
    }

    Ok(())
}

/// Check how many screen names are claimed (for early adopter threshold).
async fn count_screen_names(db: &sqlx::PgPool) -> Result<i64, ApiError> {
    let (count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM devices WHERE screen_name IS NOT NULL")
            .fetch_one(db)
            .await?;
    Ok(count)
}

#[derive(Serialize)]
pub struct CheckScreenNameResponse {
    pub available: bool,
    pub early_adopter: bool,
    pub min_length: u8,
}

/// GET /v1/screen-name/check/{name} (unauthenticated, IP rate-limited)
/// Check availability of a screen name. No auth required so the signup
/// form can check availability before the account exists.
pub async fn check_screen_name(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<Json<CheckScreenNameResponse>, ApiError> {
    // IP-based rate limit (no auth required for this endpoint)
    let ip = extract_client_ip(&headers);
    check_name_rate_limit(&state.redis, &ip).await?;

    // Anti-enumeration: pad response time
    let start = std::time::Instant::now();

    let count = count_screen_names(&state.db).await?;
    let early_adopter = count < EARLY_ADOPTER_LIMIT;
    let min_len: usize = if early_adopter { 3 } else { 5 };

    // Validate format first
    let format_ok = validate_screen_name(&name, min_len).is_ok();

    let available = if format_ok {
        let existing: Option<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT id FROM devices WHERE screen_name_lower = $1",
        )
        .bind(name.to_lowercase())
        .fetch_optional(&state.db)
        .await?;
        existing.is_none()
    } else {
        false
    };

    // Pad to minimum 200ms (anti-enumeration)
    let elapsed = start.elapsed();
    if elapsed < std::time::Duration::from_millis(200) {
        tokio::time::sleep(std::time::Duration::from_millis(200) - elapsed).await;
    }

    Ok(Json(CheckScreenNameResponse {
        available,
        early_adopter,
        min_length: min_len as u8,
    }))
}

#[derive(Deserialize)]
pub struct SetScreenNameRequest {
    pub screen_name: String,
}

#[derive(Serialize)]
pub struct SetScreenNameResponse {
    pub screen_name: String,
    pub device_id: String,
}

/// POST /v1/screen-name/set (authenticated)
/// Claim or change a screen name.
pub async fn set_screen_name(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SetScreenNameRequest>,
) -> Result<Json<SetScreenNameResponse>, ApiError> {
    let device_id = authenticate_device(
        &headers,
        "POST",
        "/v1/screen-name/set",
        &state.db,
        &state.redis,
    )
    .await?;

    let name = body.screen_name.trim().to_string();
    let name_lower = name.to_lowercase();

    // Check early adopter status
    let count = count_screen_names(&state.db).await?;
    let min_len: usize = if count < EARLY_ADOPTER_LIMIT { 3 } else { 5 };

    // Validate format
    validate_screen_name(&name, min_len)?;

    // Check 30-day cooldown (only for name CHANGES, not initial set)
    let existing: Option<(Option<String>, Option<chrono::DateTime<chrono::Utc>>)> =
        sqlx::query_as("SELECT screen_name, screen_name_changed_at FROM devices WHERE id = $1")
            .bind(device_id)
            .fetch_optional(&state.db)
            .await?;

    if let Some((Some(_old_name), Some(changed_at))) = &existing {
        let days_since = (chrono::Utc::now() - *changed_at).num_days();
        if days_since < 30 {
            return Err(ApiError::BadRequest(format!(
                "Screen name can only be changed every 30 days ({} days remaining)",
                30 - days_since
            )));
        }
    }

    // Attempt to set (unique constraint will catch conflicts)
    let result = sqlx::query(
        "UPDATE devices SET screen_name = $1, screen_name_lower = $2, screen_name_changed_at = NOW() WHERE id = $3",
    )
    .bind(&name)
    .bind(&name_lower)
    .bind(device_id)
    .execute(&state.db)
    .await;

    match result {
        Ok(r) if r.rows_affected() == 1 => Ok(Json(SetScreenNameResponse {
            screen_name: name,
            device_id: device_id.to_string(),
        })),
        Ok(_) => Err(ApiError::NotFound("device not found".into())),
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("idx_devices_screen_name_lower") || err_str.contains("unique") {
                Err(ApiError::BadRequest("That screen name is already taken".into()))
            } else {
                Err(ApiError::Internal(err_str))
            }
        }
    }
}

/// Extract client IP (same pattern as invites.rs).
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

/// Sliding window rate limit for screen name checks (unauthenticated).
async fn check_name_rate_limit(redis_client: &redis::Client, ip: &str) -> Result<(), ApiError> {
    let mut conn = match redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("redis unavailable for name check rate limit: {}", e);
            return Err(ApiError::TooManyRequests("rate limit service unavailable".into()));
        }
    };

    let key = format!("rate:screencheck:{}", ip);
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

    if count >= CHECK_RATE_LIMIT_PER_MINUTE {
        return Err(ApiError::TooManyRequests("too many checks, try again later".into()));
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
