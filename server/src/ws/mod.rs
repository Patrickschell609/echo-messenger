use std::time::Duration;

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::api::{AppState, WsOutbound};

/// Handle WebSocket upgrade for real-time message delivery.
pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_connection(socket, state))
}

/// Auth message sent by client as first WebSocket frame.
#[derive(Deserialize)]
struct WsAuthMessage {
    device_id: String,
    timestamp: String,
    nonce: String, // 16-byte random hex — prevents replay
    signature: String,
}

/// Inbound message from an authenticated client.
#[derive(Deserialize)]
#[serde(tag = "type")]
enum WsClientMessage {
    #[serde(rename = "typing")]
    Typing { recipient_device_id: String },
    #[serde(rename = "delivered")]
    Delivered {
        recipient_device_id: String,
        up_to_timestamp: i64,
    },
    #[serde(rename = "read")]
    Read {
        recipient_device_id: String,
        up_to_timestamp: i64,
    },
}

/// Response sent after authentication.
#[derive(Serialize)]
struct WsAuthResponse {
    authenticated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Timestamp tolerance for WebSocket auth: +/- 2 minutes (tightened from 5).
const AUTH_TIMESTAMP_TOLERANCE_SECS: u64 = 120;

/// Heartbeat interval.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Auth timeout: client must authenticate within 10 seconds.
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);

async fn handle_connection(mut socket: WebSocket, state: AppState) {
    // Step 1: Authenticate via first message
    let device_id = match authenticate_ws(&mut socket, &state).await {
        Ok(id) => id,
        Err(e) => {
            tracing::debug!("ws auth failed: {}", e);
            let resp = WsAuthResponse {
                authenticated: false,
                error: Some(e),
            };
            let _ = socket
                .send(Message::Text(serde_json::to_string(&resp).unwrap().into()))
                .await;
            return;
        }
    };

    // Send auth success
    let resp = WsAuthResponse {
        authenticated: true,
        error: None,
    };
    if socket
        .send(Message::Text(serde_json::to_string(&resp).unwrap().into()))
        .await
        .is_err()
    {
        return;
    }

    tracing::info!("ws connected: device {}", device_id);

    // Step 2: Register in connection map
    let (tx, mut rx) = mpsc::channel::<WsOutbound>(256);
    {
        let mut conns = state.ws_connections.write().await;
        conns.insert(device_id, tx);
    }

    // Step 3: Run message loop
    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);

    loop {
        tokio::select! {
            // Outbound: messages from send_message handler
            Some(outbound) = rx.recv() => {
                let json = match serde_json::to_string(&outbound) {
                    Ok(j) => j,
                    Err(_) => continue,
                };
                if socket.send(Message::Text(json.into())).await.is_err() {
                    break;
                }
            }
            // Inbound: pong or close from client
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Pong(_))) => {
                        // Client is alive
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        break;
                    }
                    Some(Ok(Message::Text(text))) => {
                        // Handle typed client messages (e.g. typing indicators)
                        if let Ok(client_msg) = serde_json::from_str::<WsClientMessage>(&text) {
                            match client_msg {
                                WsClientMessage::Typing { recipient_device_id } => {
                                    if let Ok(recipient) = Uuid::parse_str(&recipient_device_id) {
                                        let conns = state.ws_connections.read().await;
                                        if let Some(tx) = conns.get(&recipient) {
                                            let _ = tx.try_send(WsOutbound::Typing {
                                                sender_device_id: device_id,
                                            });
                                        }
                                    }
                                }
                                WsClientMessage::Delivered { recipient_device_id, up_to_timestamp } => {
                                    if let Ok(recipient) = Uuid::parse_str(&recipient_device_id) {
                                        let conns = state.ws_connections.read().await;
                                        if let Some(tx) = conns.get(&recipient) {
                                            let _ = tx.try_send(WsOutbound::Delivered {
                                                sender_device_id: device_id,
                                                up_to_timestamp,
                                            });
                                        }
                                    }
                                }
                                WsClientMessage::Read { recipient_device_id, up_to_timestamp } => {
                                    if let Ok(recipient) = Uuid::parse_str(&recipient_device_id) {
                                        let conns = state.ws_connections.read().await;
                                        if let Some(tx) = conns.get(&recipient) {
                                            let _ = tx.try_send(WsOutbound::Read {
                                                sender_device_id: device_id,
                                                up_to_timestamp,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Some(Err(_)) => {
                        break;
                    }
                    _ => {}
                }
            }
            // Heartbeat ping
            _ = heartbeat.tick() => {
                if socket.send(Message::Ping(vec![].into())).await.is_err() {
                    break;
                }
            }
        }
    }

    // Step 4: Cleanup on disconnect
    {
        let mut conns = state.ws_connections.write().await;
        conns.remove(&device_id);
    }
    tracing::info!("ws disconnected: device {}", device_id);
}

/// Authenticate the WebSocket connection via the first message.
/// Client sends JSON: { device_id, timestamp, signature }
/// Signature: Ed25519.sign(device_id || timestamp || "GET" || "/v1/ws")
async fn authenticate_ws(socket: &mut WebSocket, state: &AppState) -> Result<Uuid, String> {
    // Wait for auth message with timeout
    let auth_msg = tokio::time::timeout(AUTH_TIMEOUT, socket.recv())
        .await
        .map_err(|_| "auth timeout".to_string())?
        .ok_or_else(|| "connection closed before auth".to_string())?
        .map_err(|e| format!("ws error: {}", e))?;

    let text = match auth_msg {
        Message::Text(t) => t.to_string(),
        _ => return Err("first message must be text".into()),
    };

    let auth: WsAuthMessage =
        serde_json::from_str(&text).map_err(|_| "invalid auth JSON".to_string())?;

    let device_id =
        Uuid::parse_str(&auth.device_id).map_err(|_| "invalid device_id".to_string())?;

    let timestamp: u64 = auth
        .timestamp
        .parse()
        .map_err(|_| "invalid timestamp".to_string())?;

    let sig_bytes =
        hex::decode(&auth.signature).map_err(|_| "invalid signature hex".to_string())?;

    if sig_bytes.len() != 64 {
        return Err("signature must be 64 bytes".into());
    }

    // Check timestamp freshness
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let diff = if now > timestamp {
        now - timestamp
    } else {
        timestamp - now
    };
    if diff > AUTH_TIMESTAMP_TOLERANCE_SECS {
        return Err("timestamp expired".into());
    }

    // Validate and check nonce for replay protection
    let nonce_bytes = hex::decode(&auth.nonce).map_err(|_| "invalid nonce hex".to_string())?;
    if nonce_bytes.len() != 16 {
        return Err("nonce must be 16 bytes".into());
    }

    // Check nonce uniqueness via Redis (same pattern as HTTP auth)
    let nonce_key = format!("auth:ws:nonce:{}", auth.nonce);
    match state.redis.get_multiplexed_async_connection().await {
        Ok(mut conn) => {
            let was_set: bool = redis::cmd("SET")
                .arg(&nonce_key)
                .arg("1")
                .arg("NX")
                .arg("EX")
                .arg(AUTH_TIMESTAMP_TOLERANCE_SECS * 2)
                .query_async(&mut conn)
                .await
                .unwrap_or(false);
            if !was_set {
                return Err("nonce already used (replay)".into());
            }
        }
        Err(e) => {
            return Err(format!("auth service unavailable: {}", e));
        }
    }

    // Look up identity key
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT identity_key FROM devices WHERE id = $1")
            .bind(device_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| format!("db error: {}", e))?;

    let (identity_key_bytes,) = row.ok_or_else(|| "device not found".to_string())?;

    if identity_key_bytes.len() != 32 {
        return Err("stored identity_key wrong size".into());
    }

    // Build the signed message: device_id || timestamp || nonce || "GET" || "/v1/ws"
    let mut message = Vec::new();
    message.extend_from_slice(auth.device_id.as_bytes());
    message.extend_from_slice(auth.timestamp.as_bytes());
    message.extend_from_slice(auth.nonce.as_bytes());
    message.extend_from_slice(b"GET");
    message.extend_from_slice(b"/v1/ws");

    // Verify Ed25519 signature
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(&identity_key_bytes);
    let verifying_key =
        VerifyingKey::from_bytes(&pk_bytes).map_err(|_| "invalid stored public key".to_string())?;

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key
        .verify(&message, &signature)
        .map_err(|_| "signature verification failed".to_string())?;

    Ok(device_id)
}
