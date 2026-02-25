use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{authenticate_device, ApiError, AppState};

/// Maximum sealed envelope size: 64 KiB.
const MAX_ENVELOPE_SIZE: usize = 65536;

/// Rate limit: max sealed-sender sends per minute per IP.
const RATE_LIMIT_PER_MINUTE: i64 = 100;

/// Maximum queued messages per recipient device.
const MAX_QUEUE_DEPTH: i64 = 10_000;

/// POST /v1/messages/send
/// Submit a sealed sender envelope. The server cannot read it.
/// NO authentication required — sealed sender means the server doesn't know who's sending.
#[derive(Deserialize)]
pub struct SendMessageRequest {
    pub recipient_device_id: Uuid,
    /// Sealed sender envelope (opaque bytes, hex-encoded)
    pub envelope: String,
}

#[derive(Serialize)]
pub struct SendMessageResponse {
    pub queued: bool,
    pub timestamp: i64,
}

/// Sliding window rate limit check via Redis sorted sets.
/// Fails CLOSED (rejects request) if Redis is unavailable.
async fn check_send_rate_limit(redis_client: &redis::Client, ip: &str) -> Result<(), ApiError> {
    let mut conn = match redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("redis unavailable for rate limit, rejecting: {}", e);
            return Err(ApiError::TooManyRequests("rate limit service unavailable".into()));
        }
    };

    let key = format!("rate:send:{}", ip);
    let now_ms = chrono::Utc::now().timestamp_millis();
    let window_start = now_ms - 60_000;

    // Clean entries older than 60s
    redis::cmd("ZREMRANGEBYSCORE")
        .arg(&key)
        .arg("-inf")
        .arg(window_start)
        .query_async::<()>(&mut conn)
        .await
        .ok();

    // Count requests in current window
    let count: i64 = redis::cmd("ZCARD")
        .arg(&key)
        .query_async(&mut conn)
        .await
        .unwrap_or(0);

    if count >= RATE_LIMIT_PER_MINUTE {
        return Err(ApiError::TooManyRequests(
            "rate limit exceeded, try again later".into(),
        ));
    }

    // Record this request with a unique member
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

/// Extract client IP for rate limiting.
/// SECURITY: Never trust X-Forwarded-For or X-Real-IP directly — clients can spoof them.
/// Only use proxy headers if TRUSTED_PROXY_CIDRS env var is configured and the connection
/// comes from a trusted proxy. Otherwise use the peer address from ConnectInfo.
///
/// For now, we fall back to "unknown" which groups all non-proxied clients together.
/// In production, pass the real peer IP via axum::extract::ConnectInfo<SocketAddr>.
fn extract_client_ip(headers: &HeaderMap, peer_addr: Option<&str>) -> String {
    // If we have a direct peer address, prefer it (not spoofable)
    if let Some(addr) = peer_addr {
        return addr.to_string();
    }

    // Only trust proxy headers if TRUSTED_PROXIES is configured
    let trusted = std::env::var("TRUSTED_PROXY_CIDRS").unwrap_or_default();
    if trusted.is_empty() {
        // No trusted proxies configured — ignore XFF/X-Real-IP entirely
        return "unknown".to_string();
    }

    // If behind a trusted proxy, use X-Real-IP (set by the proxy, not the client)
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub async fn send_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SendMessageRequest>,
) -> Result<Json<SendMessageResponse>, ApiError> {
    // IP-based rate limit (AV-10)
    let ip = extract_client_ip(&headers, None); // TODO: pass ConnectInfo peer addr
    check_send_rate_limit(&state.redis, &ip).await?;

    let envelope = hex::decode(&req.envelope)
        .map_err(|_| ApiError::BadRequest("invalid envelope hex".into()))?;

    if envelope.is_empty() {
        return Err(ApiError::BadRequest("empty envelope".into()));
    }

    if envelope.len() > MAX_ENVELOPE_SIZE {
        return Err(ApiError::PayloadTooLarge(format!(
            "envelope exceeds {} byte limit",
            MAX_ENVELOPE_SIZE
        )));
    }

    // Verify recipient device exists
    let exists: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM devices WHERE id = $1"
    )
    .bind(req.recipient_device_id)
    .fetch_optional(&state.db)
    .await?;

    if exists.is_none() {
        return Err(ApiError::NotFound("recipient device not found".into()));
    }

    // Atomic queue depth check + insert with TTL (prevents TOCTOU race + harvest-now-decrypt-later)
    // Messages expire after 30 days — prevents indefinite accumulation on seized servers
    let insert_result: Option<(i64, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        r#"
        INSERT INTO message_queue (recipient_device_id, envelope, expires_at)
        SELECT $1, $2, NOW() + INTERVAL '30 days'
        WHERE (SELECT COUNT(*) FROM message_queue WHERE recipient_device_id = $1) < $3
        RETURNING id, queued_at
        "#
    )
    .bind(req.recipient_device_id)
    .bind(&envelope)
    .bind(MAX_QUEUE_DEPTH)
    .fetch_optional(&state.db)
    .await?;

    let (msg_id, queued_at) = match insert_result {
        Some(row) => row,
        None => return Err(ApiError::TooManyRequests("recipient queue full".into())),
    };

    tracing::debug!(
        "queued message for device {} ({} bytes)",
        req.recipient_device_id,
        envelope.len()
    );

    // Push via WebSocket if recipient is connected
    {
        let conns = state.ws_connections.read().await;
        if let Some(tx) = conns.get(&req.recipient_device_id) {
            let ws_msg = super::WsOutbound::NewMessage {
                id: msg_id,
                envelope: req.envelope.clone(),
                queued_at: queued_at.timestamp(),
            };
            // Best-effort: don't fail the send if WS push fails
            let _ = tx.try_send(ws_msg);
        }
    }

    Ok(Json(SendMessageResponse {
        queued: true,
        timestamp: queued_at.timestamp(),
    }))
}

/// GET /v1/messages/receive
/// Pull all queued messages for the authenticated device.
#[derive(Serialize)]
pub struct ReceiveMessagesResponse {
    pub messages: Vec<QueuedMessage>,
}

#[derive(Serialize)]
pub struct QueuedMessage {
    pub id: i64,
    /// Sealed sender envelope (hex)
    pub envelope: String,
    pub queued_at: i64,
}

pub async fn receive_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ReceiveMessagesResponse>, ApiError> {
    let device_id = authenticate_device(
        &headers,
        "GET",
        "/v1/messages/receive",
        &state.db,
        &state.redis,
    ).await?;

    // Fetch queued messages, oldest first, limit 100
    let rows: Vec<(i64, Vec<u8>, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        r#"
        SELECT id, envelope, queued_at
        FROM message_queue
        WHERE recipient_device_id = $1
        ORDER BY queued_at ASC
        LIMIT 100
        "#
    )
    .bind(device_id)
    .fetch_all(&state.db)
    .await?;

    // Update last_seen
    sqlx::query("UPDATE devices SET last_seen = NOW() WHERE id = $1")
        .bind(device_id)
        .execute(&state.db)
        .await?;

    let messages: Vec<QueuedMessage> = rows
        .into_iter()
        .map(|(id, envelope, queued_at)| QueuedMessage {
            id,
            envelope: hex::encode(&envelope),
            queued_at: queued_at.timestamp(),
        })
        .collect();

    Ok(Json(ReceiveMessagesResponse { messages }))
}

/// POST /v1/messages/ack
/// Acknowledge receipt of messages, removing them from the queue.
#[derive(Deserialize)]
pub struct AckMessageRequest {
    pub message_ids: Vec<i64>,
}

#[derive(Serialize)]
pub struct AckMessageResponse {
    pub deleted: u64,
}

pub async fn ack_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AckMessageRequest>,
) -> Result<Json<AckMessageResponse>, ApiError> {
    let device_id = authenticate_device(
        &headers,
        "POST",
        "/v1/messages/ack",
        &state.db,
        &state.redis,
    ).await?;

    if req.message_ids.is_empty() {
        return Ok(Json(AckMessageResponse { deleted: 0 }));
    }

    // Delete only messages that belong to this device (prevents cross-device deletion)
    let result = sqlx::query(
        r#"
        DELETE FROM message_queue
        WHERE id = ANY($1) AND recipient_device_id = $2
        "#
    )
    .bind(&req.message_ids)
    .bind(device_id)
    .execute(&state.db)
    .await?;

    Ok(Json(AckMessageResponse {
        deleted: result.rows_affected(),
    }))
}
