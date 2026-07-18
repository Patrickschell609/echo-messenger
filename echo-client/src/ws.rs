//! WebSocket client for real-time message delivery and typing indicators.

use anyhow::{anyhow, Result};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite;
use uuid::Uuid;

/// Inbound WebSocket message from server.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type")]
pub enum WsInbound {
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

/// Outbound WebSocket message to server.
#[derive(Serialize)]
#[serde(tag = "type")]
pub enum WsOutbound {
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

/// Auth message sent to server.
#[derive(Serialize)]
struct WsAuthMessage {
    device_id: String,
    timestamp: String,
    nonce: String,
    signature: String,
    #[serde(default)]
    ml_dsa_signature: String,
}

/// Auth response from server.
#[derive(Deserialize)]
struct WsAuthResponse {
    authenticated: bool,
    error: Option<String>,
}

pub struct WsClient {
    ws_url: String,
    device_id: Uuid,
    ed25519_private: [u8; 32],
    ml_dsa_private: Vec<u8>,
}

impl WsClient {
    pub fn new(base_url: &str, device_id: Uuid, ed25519_private: &[u8; 32], ml_dsa_private: &[u8]) -> Self {
        // Convert http(s):// to ws(s)://
        let ws_url = if base_url.starts_with("https://") {
            base_url.replacen("https://", "wss://", 1)
        } else {
            base_url.replacen("http://", "ws://", 1)
        };
        let ws_url = format!("{}/v1/ws", ws_url.trim_end_matches('/'));

        Self {
            ws_url,
            device_id,
            ed25519_private: *ed25519_private,
            ml_dsa_private: ml_dsa_private.to_vec(),
        }
    }

    /// Connect to the WebSocket server, authenticate, and return channels.
    /// Returns (inbound receiver, outbound sender, read loop JoinHandle).
    pub async fn connect(
        &self,
    ) -> Result<(
        mpsc::Receiver<WsInbound>,
        mpsc::Sender<WsOutbound>,
        tokio::task::JoinHandle<()>,
    )> {
        let (ws_stream, _response) = tokio_tungstenite::connect_async(&self.ws_url)
            .await
            .map_err(|e| anyhow!("ws connect failed: {}", e))?;

        let (mut write, mut read) = ws_stream.split();

        // Send auth message
        let auth_msg = self.build_auth_message();
        let auth_json = serde_json::to_string(&auth_msg)?;
        write
            .send(tungstenite::Message::Text(auth_json.into()))
            .await
            .map_err(|e| anyhow!("ws send auth failed: {}", e))?;

        // Wait for auth response
        let auth_resp_msg = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            read.next(),
        )
        .await
        .map_err(|_| anyhow!("ws auth response timeout"))?
        .ok_or_else(|| anyhow!("ws closed before auth response"))?
        .map_err(|e| anyhow!("ws read error: {}", e))?;

        let auth_text = match auth_resp_msg {
            tungstenite::Message::Text(t) => t.to_string(),
            _ => return Err(anyhow!("expected text auth response")),
        };

        let auth_resp: WsAuthResponse = serde_json::from_str(&auth_text)?;
        if !auth_resp.authenticated {
            return Err(anyhow!(
                "ws auth rejected: {}",
                auth_resp.error.unwrap_or_default()
            ));
        }

        // Channels
        let (inbound_tx, inbound_rx) = mpsc::channel::<WsInbound>(256);
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<WsOutbound>(64);

        // Spawn combined read/write loop
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Read from server
                    msg = read.next() => {
                        match msg {
                            Some(Ok(tungstenite::Message::Text(text))) => {
                                if let Ok(inbound) = serde_json::from_str::<WsInbound>(&text) {
                                    if inbound_tx.send(inbound).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            Some(Ok(tungstenite::Message::Ping(_))) => {}
                            Some(Ok(tungstenite::Message::Close(_))) | None => {
                                break;
                            }
                            Some(Err(_)) => {
                                break;
                            }
                            _ => {}
                        }
                    }
                    // Write to server (outbound from app)
                    Some(outbound) = outbound_rx.recv() => {
                        if let Ok(json) = serde_json::to_string(&outbound) {
                            if write.send(tungstenite::Message::Text(json.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok((inbound_rx, outbound_tx, handle))
    }

    fn build_auth_message(&self) -> WsAuthMessage {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let timestamp_str = timestamp.to_string();
        let device_id_str = self.device_id.to_string();

        // Generate random nonce for replay protection
        let mut nonce_bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
        let nonce_hex = hex::encode(nonce_bytes);

        let mut message = Vec::new();
        message.extend_from_slice(device_id_str.as_bytes());
        message.extend_from_slice(timestamp_str.as_bytes());
        message.extend_from_slice(nonce_hex.as_bytes());
        message.extend_from_slice(b"GET");
        message.extend_from_slice(b"/v1/ws");

        use ed25519_dalek::Signer;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&self.ed25519_private);
        let signature = signing_key.sign(&message);
        let sig_hex = hex::encode(signature.to_bytes());

        // Post-quantum half: ML-DSA-87 signature over the same message.
        let ml_dsa_sig_hex = if !self.ml_dsa_private.is_empty() {
            hex::encode(
                echo_crypto::crypto::pq_sign::pq_sign(&self.ml_dsa_private, &message)
                    .unwrap_or_default(),
            )
        } else {
            String::new()
        };

        WsAuthMessage {
            device_id: device_id_str,
            timestamp: timestamp_str,
            nonce: nonce_hex,
            signature: sig_hex,
            ml_dsa_signature: ml_dsa_sig_hex,
        }
    }
}
