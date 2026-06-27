use tauri::{AppHandle, Emitter, Manager};
use base64::Engine as _;

use echo_client::http::HttpClient;
use echo_client::identity;
use echo_client::identity::SessionMeta;
use echo_client::wire::{ConversationSettings, WireMessage};
use echo_crypto::ratchet::state::RatchetState;

use crate::events;
use crate::state::{AppState, ChatMessage};

const MEDIA_TEXT_PREFIX: &str = "ECHO_MEDIA:";

pub(crate) fn media_dir() -> std::path::PathBuf {
    let dir = dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join("echo-app")
        .join("media");
    std::fs::create_dir_all(&dir).ok();
    dir
}

pub(crate) fn build_media_text(mime: &str, filename: &str, path: &str) -> String {
    format!(
        "{}{}",
        MEDIA_TEXT_PREFIX,
        serde_json::json!({ "mime": mime, "filename": filename, "path": path })
    )
}

/// Parse media metadata from history text. Returns (display_text, media_url, media_mime, media_filename).
pub(crate) fn parse_media_text(text: &str) -> (String, Option<String>, Option<String>, Option<String>) {
    if let Some(json_str) = text.strip_prefix(MEDIA_TEXT_PREFIX) {
        if let Ok(meta) = serde_json::from_str::<serde_json::Value>(json_str) {
            let mime = meta.get("mime").and_then(|v| v.as_str()).map(|s| s.to_string());
            let filename = meta.get("filename").and_then(|v| v.as_str()).map(|s| s.to_string());
            let path = meta.get("path").and_then(|v| v.as_str());
            let data_url = path.and_then(|p| {
                let bytes = std::fs::read(p).ok()?;
                let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                let m = mime.as_deref().unwrap_or("application/octet-stream");
                Some(format!("data:{};base64,{}", m, b64))
            });
            let display = filename.clone().unwrap_or_else(|| "File".to_string());
            return (display, data_url, mime, filename);
        }
    }
    (text.to_string(), None, None, None)
}

/// Send an encrypted message to a device.
#[tauri::command]
pub async fn send_message(
    app: AppHandle,
    device_id: String,
    message: String,
) -> Result<ChatMessage, String> {
    let state = app.state::<AppState>();

    let identity_state = {
        let id = state.identity.lock().unwrap();
        id.clone().ok_or("Not signed in")?
    };

    let http = {
        let h = state.http.lock().unwrap();
        match h.as_ref() {
            Some(http) => {
                let mut ed_bytes = [0u8; 32];
                ed_bytes.copy_from_slice(&identity_state.identity_ed_private);
                HttpClient::with_auth(http.base_url(), identity_state.device_id, &ed_bytes)
            }
            None => return Err("Not connected".to_string()),
        }
    };

    let recipient_device: uuid::Uuid = device_id.parse().map_err(|e| format!("Invalid UUID: {}", e))?;

    // Load session from vault (lock + release before await)
    let (ratchet_state_loaded, session_meta_loaded): (RatchetState, SessionMeta) = {
        let vault = state.vault.lock().unwrap();
        vault
            .load_session(recipient_device)
            .map_err(|e| format!("No session: {}", e))?
    };

    tracing::info!(
        "◀ SEND to {} — needs_prekey={}, send_chain={}, recv_chain={}, dh_num={}, send_n={}, recv_n={}",
        recipient_device,
        session_meta_loaded.needs_prekey_message,
        ratchet_state_loaded.sending_chain_key.is_some(),
        ratchet_state_loaded.receiving_chain_key.is_some(),
        ratchet_state_loaded.dh_ratchet_number,
        ratchet_state_loaded.send_message_number,
        ratchet_state_loaded.recv_message_number,
    );

    // Encrypt (sync, no lock needed)
    let mut session = echo_crypto::ratchet::TripleRatchetSession::new(ratchet_state_loaded);
    let encrypted = session.encrypt(message.as_bytes()).map_err(|e| {
        tracing::error!("◀ SEND ENCRYPT FAILED to {}: {}", recipient_device, e);
        e.to_string()
    })?;

    let header_bytes = bincode::serialize(&encrypted.header).map_err(|e| e.to_string())?;
    let wire_type = if session_meta_loaded.needs_prekey_message { "PreKey" } else { "Normal" };
    tracing::info!("◀ SEND to {} — encrypt OK, wire type={}, msg_len={}", recipient_device, wire_type, message.len());
    let wire_msg = if session_meta_loaded.needs_prekey_message {
        WireMessage::PreKey {
            sender_identity_key: identity_state.identity_ed_public.clone(),
            sender_identity_dh_key: identity_state.identity_dh_public.clone(),
            sender_identity_dh_signature: identity::sign_identity_dh_binding(&identity_state),
            ephemeral_public: session_meta_loaded.ephemeral_public.clone(),
            pq_ciphertext: session_meta_loaded.pq_ciphertext.clone(),
            used_one_time_prekey_id: session_meta_loaded.used_one_time_prekey_id,
            ratchet_header: header_bytes,
            encrypted_header: encrypted.encrypted_header,
            ciphertext: encrypted.ciphertext,
        }
    } else {
        WireMessage::Normal {
            ratchet_header: header_bytes,
            encrypted_header: encrypted.encrypted_header,
            ciphertext: encrypted.ciphertext,
        }
    };

    let wire_payload = bincode::serialize(&wire_msg).map_err(|e| e.to_string())?;

    // M4 (Apr 21 audit): require the server-signed sender cert. A self-built cert
    // carries a zero server_signature, which the recipient's unseal_message() rejects
    // (sealed_sender::verify_sender_cert). Silently shipping one means the message is
    // dropped on the far end with the sender none the wiser — hard-fail instead.
    let cert: echo_crypto::sealed_sender::SenderCertificate = {
        let vault = state.vault.lock().unwrap();
        vault.load_sender_cert().ok_or_else(|| {
            "missing server-signed sender certificate — re-register to obtain one".to_string()
        })?
    };
    let envelope = echo_crypto::sealed_sender::seal_message(
        &session_meta_loaded.recipient_dh_key,
        &cert,
        &wire_payload,
    )
    .map_err(|e| e.to_string())?;

    let envelope_bytes = bincode::serialize(&envelope).map_err(|e| e.to_string())?;

    // Persist ratchet state BEFORE network send — prevents nonce reuse on retry (AV-06)
    {
        let ratchet_state = session.export_state().clone();
        let mut session_meta = session_meta_loaded.clone();
        session_meta.needs_prekey_message = false;

        let vault = state.vault.lock().unwrap();
        vault
            .save_session(recipient_device, &ratchet_state, &session_meta)
            .map_err(|e| format!("failed to persist ratchet: {}", e))?;
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let msg_id = format!("{}-sent-{}", device_id, now);

    // Try to send — on failure, queue to outbox instead of returning error
    let status = match http.send_message(recipient_device, &envelope_bytes).await {
        Ok(()) => {
            tracing::info!("◀ SEND to {} — delivered to server OK", recipient_device);
            0u8 // sent
        }
        Err(e) => {
            tracing::warn!("◀ SEND to {} — server rejected, queuing to outbox: {}", recipient_device, e);
            let outbox = state.outbox.lock().unwrap();
            if let Some(ref ob) = *outbox {
                ob.queue_message(&device_id, &msg_id, &envelope_bytes)
                    .map_err(|e| e.to_string())?;
            }
            3u8 // queued
        }
    };

    // Check conversation timer for auto-delete expiry
    let expires_at = {
        let vault = state.vault.lock().unwrap();
        let settings: ConversationSettings = vault
            .read_file(&format!("conversations/{}.enc", device_id))
            .unwrap_or_default();
        if settings.auto_delete_secs > 0 {
            Some(now + settings.auto_delete_secs)
        } else {
            None
        }
    };

    // Insert into encrypted history (with optional expiry)
    {
        let history = state.history.lock().unwrap();
        if let Some(ref h) = *history {
            h.insert_message_with_expiry(&msg_id, &device_id, &message, true, now, expires_at).ok();
            if status == 3 {
                h.set_message_status(&msg_id, 3).ok();
            }
        }
    }

    Ok(ChatMessage {
        id: msg_id,
        from_device: identity_state.device_id.to_string(),
        text: message,
        sent_by_me: true,
        timestamp: now,
        status,
        edited: false,
        media_url: None,
        media_mime: None,
        media_filename: None,
    })
}

/// Load chat history for a peer (paginated, decrypted from SQLite).
#[tauri::command]
pub async fn load_chat_history(
    app: AppHandle,
    device_id: String,
    limit: u32,
    before_timestamp: Option<u64>,
) -> Result<Vec<ChatMessage>, String> {
    let state = app.state::<AppState>();

    let identity_device = {
        let id = state.identity.lock().unwrap();
        id.as_ref().map(|i| i.device_id.to_string()).unwrap_or_default()
    };

    let msgs = {
        let history = state.history.lock().unwrap();
        let h = history.as_ref().ok_or("Not signed in".to_string())?;
        h.load_messages(&device_id, limit, before_timestamp)
            .map_err(|e| e.to_string())?
    };

    Ok(msgs
        .into_iter()
        .map(|m| {
            // Detect media messages stored in history
            let (text, media_url, media_mime, media_filename) = parse_media_text(&m.text);
            ChatMessage {
                id: format!("hist-{}", m.id),
                from_device: if m.sent_by_me {
                    identity_device.clone()
                } else {
                    m.peer_id.clone()
                },
                text,
                sent_by_me: m.sent_by_me,
                timestamp: m.timestamp,
                status: m.status,
                edited: m.edited,
                media_url,
                media_mime,
                media_filename,
            }
        })
        .collect())
}

/// Mark messages from a peer as read and send a read receipt via WebSocket.
#[tauri::command]
pub async fn mark_messages_read(
    app: AppHandle,
    device_id: String,
) -> Result<(), String> {
    let state = app.state::<AppState>();

    // Get the max received timestamp for this peer
    let max_ts = {
        let history = state.history.lock().unwrap();
        match history.as_ref() {
            Some(h) => h.max_received_timestamp(&device_id).ok().flatten(),
            None => None,
        }
    };

    // Send read receipt via WS if we have a timestamp
    if let Some(ts) = max_ts {
        let ws_tx = {
            let tx = state.ws_tx.lock().unwrap();
            tx.clone()
        };
        if let Some(tx) = ws_tx {
            let _ = tx.try_send(echo_client::ws::WsOutbound::Read {
                recipient_device_id: device_id,
                up_to_timestamp: ts as i64,
            });
        }
    }

    Ok(())
}

/// Send a typing indicator via WebSocket (WS-only, graceful no-op if polling).
#[tauri::command]
pub async fn send_typing_indicator(
    app: AppHandle,
    device_id: String,
) -> Result<(), String> {
    let state = app.state::<AppState>();

    let ws_tx = {
        let tx = state.ws_tx.lock().unwrap();
        tx.clone()
    };

    if let Some(tx) = ws_tx {
        let _ = tx.try_send(echo_client::ws::WsOutbound::Typing {
            recipient_device_id: device_id,
        });
    }
    // If not connected via WS, silently skip — typing is WS-only
    Ok(())
}

/// Get current device ID (for display).
#[tauri::command]
pub fn get_device_id(app: AppHandle) -> Result<String, String> {
    let state = app.state::<AppState>();
    let id = state.identity.lock().unwrap();
    match id.as_ref() {
        Some(s) => Ok(s.device_id.to_string()),
        None => Err("Not signed in".to_string()),
    }
}

/// Send an encrypted file/image to a device.
#[tauri::command]
pub async fn send_file(
    app: AppHandle,
    device_id: String,
    file_data: String,
    filename: String,
    mime_type: String,
) -> Result<ChatMessage, String> {
    let file_bytes = base64::engine::general_purpose::STANDARD
        .decode(&file_data)
        .map_err(|e| format!("Invalid file data: {}", e))?;

    if file_bytes.len() > 5 * 1024 * 1024 {
        return Err("File too large (max 5MB)".to_string());
    }

    let state = app.state::<AppState>();

    let identity_state = {
        let id = state.identity.lock().unwrap();
        id.clone().ok_or("Not signed in")?
    };

    let http = {
        let h = state.http.lock().unwrap();
        match h.as_ref() {
            Some(http) => {
                let mut ed_bytes = [0u8; 32];
                ed_bytes.copy_from_slice(&identity_state.identity_ed_private);
                HttpClient::with_auth(http.base_url(), identity_state.device_id, &ed_bytes)
            }
            None => return Err("Not connected".to_string()),
        }
    };

    let recipient_device: uuid::Uuid =
        device_id.parse().map_err(|e| format!("Invalid UUID: {}", e))?;

    // Build media payload
    let media = echo_client::wire::MediaContent {
        mime_type: mime_type.clone(),
        filename: filename.clone(),
        data: file_bytes.clone(),
    };
    let payload = media.encode();

    // Load session from vault
    let (ratchet_state_loaded, session_meta_loaded): (RatchetState, SessionMeta) = {
        let vault = state.vault.lock().unwrap();
        vault
            .load_session(recipient_device)
            .map_err(|e| format!("No session: {}", e))?
    };

    // Encrypt media payload
    let mut session = echo_crypto::ratchet::TripleRatchetSession::new(ratchet_state_loaded);
    let encrypted = session.encrypt(&payload).map_err(|e| e.to_string())?;

    let header_bytes = bincode::serialize(&encrypted.header).map_err(|e| e.to_string())?;
    let wire_msg = if session_meta_loaded.needs_prekey_message {
        WireMessage::PreKey {
            sender_identity_key: identity_state.identity_ed_public.clone(),
            sender_identity_dh_key: identity_state.identity_dh_public.clone(),
            sender_identity_dh_signature: identity::sign_identity_dh_binding(&identity_state),
            ephemeral_public: session_meta_loaded.ephemeral_public.clone(),
            pq_ciphertext: session_meta_loaded.pq_ciphertext.clone(),
            used_one_time_prekey_id: session_meta_loaded.used_one_time_prekey_id,
            ratchet_header: header_bytes,
            encrypted_header: encrypted.encrypted_header,
            ciphertext: encrypted.ciphertext,
        }
    } else {
        WireMessage::Normal {
            ratchet_header: header_bytes,
            encrypted_header: encrypted.encrypted_header,
            ciphertext: encrypted.ciphertext,
        }
    };

    let wire_payload = bincode::serialize(&wire_msg).map_err(|e| e.to_string())?;

    // M4 (Apr 21 audit): require the server-signed sender cert — a self-built fallback
    // has a zero server_signature and is rejected by the recipient, silently dropping
    // the message. Hard-fail instead.
    let cert: echo_crypto::sealed_sender::SenderCertificate = {
        let vault = state.vault.lock().unwrap();
        vault.load_sender_cert().ok_or_else(|| {
            "missing server-signed sender certificate — re-register to obtain one".to_string()
        })?
    };
    let envelope = echo_crypto::sealed_sender::seal_message(
        &session_meta_loaded.recipient_dh_key,
        &cert,
        &wire_payload,
    )
    .map_err(|e| e.to_string())?;

    let envelope_bytes = bincode::serialize(&envelope).map_err(|e| e.to_string())?;

    // Persist ratchet state BEFORE network send (AV-06)
    {
        let ratchet_state = session.export_state().clone();
        let mut session_meta = session_meta_loaded.clone();
        session_meta.needs_prekey_message = false;

        let vault = state.vault.lock().unwrap();
        vault
            .save_session(recipient_device, &ratchet_state, &session_meta)
            .map_err(|e| format!("failed to persist ratchet: {}", e))?;
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Save file locally
    let peer_dir = media_dir().join(&device_id);
    std::fs::create_dir_all(&peer_dir).map_err(|e| e.to_string())?;
    // Sanitize filename: strip path separators, traversal, and non-printable chars
    let safe_name: String = filename
        .replace(['/', '\\', '\0', ':', '<', '>', '|', '"', '?', '*'], "_")
        .replace("..", "_")
        .trim_matches(|c: char| c == '.' || c == ' ' || c == '_')
        .to_string();
    let safe_name = if safe_name.is_empty() { "file".to_string() } else { safe_name };
    let local_path = peer_dir.join(format!("{}_{}", now, safe_name));
    std::fs::write(&local_path, &file_bytes).map_err(|e| format!("Save media: {}", e))?;

    let media_text = build_media_text(&mime_type, &filename, &local_path.to_string_lossy());
    let msg_id = format!("{}-sent-{}", device_id, now);

    // Send
    let status = match http.send_message(recipient_device, &envelope_bytes).await {
        Ok(()) => 0u8,
        Err(e) => {
            tracing::warn!("send failed, queuing to outbox: {}", e);
            let outbox = state.outbox.lock().unwrap();
            if let Some(ref ob) = *outbox {
                ob.queue_message(&device_id, &msg_id, &envelope_bytes)
                    .map_err(|e| e.to_string())?;
            }
            3u8
        }
    };

    // Check conversation timer for auto-delete expiry
    let expires_at = {
        let vault = state.vault.lock().unwrap();
        let settings: ConversationSettings = vault
            .read_file(&format!("conversations/{}.enc", device_id))
            .unwrap_or_default();
        if settings.auto_delete_secs > 0 {
            Some(now + settings.auto_delete_secs)
        } else {
            None
        }
    };

    // Insert media metadata into history (with optional expiry)
    {
        let history = state.history.lock().unwrap();
        if let Some(ref h) = *history {
            h.insert_message_with_expiry(&msg_id, &device_id, &media_text, true, now, expires_at).ok();
            if status == 3 {
                h.set_message_status(&msg_id, 3).ok();
            }
        }
    }

    // Build data URL for immediate display
    let b64 = base64::engine::general_purpose::STANDARD.encode(&file_bytes);
    let data_url = format!("data:{};base64,{}", mime_type, b64);

    Ok(ChatMessage {
        id: msg_id,
        from_device: identity_state.device_id.to_string(),
        text: filename.clone(),
        sent_by_me: true,
        timestamp: now,
        status,
        edited: false,
        media_url: Some(data_url),
        media_mime: Some(mime_type),
        media_filename: Some(filename),
    })
}

/// Helper: encrypt a payload and send via sealed sender to a device.
/// Used by control message commands.
async fn send_encrypted_payload(
    app: &AppHandle,
    device_id: &str,
    payload: &[u8],
) -> Result<(), String> {
    let state = app.state::<AppState>();

    let identity_state = {
        let id = state.identity.lock().unwrap();
        id.clone().ok_or("Not signed in")?
    };

    let http = {
        let h = state.http.lock().unwrap();
        match h.as_ref() {
            Some(http) => {
                let mut ed_bytes = [0u8; 32];
                ed_bytes.copy_from_slice(&identity_state.identity_ed_private);
                HttpClient::with_auth(http.base_url(), identity_state.device_id, &ed_bytes)
            }
            None => return Err("Not connected".to_string()),
        }
    };

    let recipient_device: uuid::Uuid =
        device_id.parse().map_err(|e| format!("Invalid UUID: {}", e))?;

    let (ratchet_state_loaded, session_meta_loaded): (RatchetState, SessionMeta) = {
        let vault = state.vault.lock().unwrap();
        vault
            .load_session(recipient_device)
            .map_err(|e| format!("No session: {}", e))?
    };

    let mut session = echo_crypto::ratchet::TripleRatchetSession::new(ratchet_state_loaded);
    let encrypted = session.encrypt(payload).map_err(|e| e.to_string())?;

    let header_bytes = bincode::serialize(&encrypted.header).map_err(|e| e.to_string())?;
    let wire_msg = if session_meta_loaded.needs_prekey_message {
        WireMessage::PreKey {
            sender_identity_key: identity_state.identity_ed_public.clone(),
            sender_identity_dh_key: identity_state.identity_dh_public.clone(),
            sender_identity_dh_signature: identity::sign_identity_dh_binding(&identity_state),
            ephemeral_public: session_meta_loaded.ephemeral_public.clone(),
            pq_ciphertext: session_meta_loaded.pq_ciphertext.clone(),
            used_one_time_prekey_id: session_meta_loaded.used_one_time_prekey_id,
            ratchet_header: header_bytes,
            encrypted_header: encrypted.encrypted_header,
            ciphertext: encrypted.ciphertext,
        }
    } else {
        WireMessage::Normal {
            ratchet_header: header_bytes,
            encrypted_header: encrypted.encrypted_header,
            ciphertext: encrypted.ciphertext,
        }
    };

    let wire_payload = bincode::serialize(&wire_msg).map_err(|e| e.to_string())?;

    // M4 (Apr 21 audit): require the server-signed sender cert — a self-built fallback
    // has a zero server_signature and is rejected by the recipient, silently dropping
    // the message. Hard-fail instead.
    let cert: echo_crypto::sealed_sender::SenderCertificate = {
        let vault = state.vault.lock().unwrap();
        vault.load_sender_cert().ok_or_else(|| {
            "missing server-signed sender certificate — re-register to obtain one".to_string()
        })?
    };
    let envelope = echo_crypto::sealed_sender::seal_message(
        &session_meta_loaded.recipient_dh_key,
        &cert,
        &wire_payload,
    )
    .map_err(|e| e.to_string())?;

    let envelope_bytes = bincode::serialize(&envelope).map_err(|e| e.to_string())?;

    // Persist ratchet state BEFORE network send (AV-06)
    {
        let ratchet_state = session.export_state().clone();
        let mut session_meta = session_meta_loaded.clone();
        session_meta.needs_prekey_message = false;

        let vault = state.vault.lock().unwrap();
        vault
            .save_session(recipient_device, &ratchet_state, &session_meta)
            .map_err(|e| format!("failed to persist ratchet: {}", e))?;
    }

    http.send_message(recipient_device, &envelope_bytes)
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// Set auto-delete timer for a conversation.
#[tauri::command]
pub async fn set_auto_delete(
    app: AppHandle,
    device_id: String,
    duration_secs: u64,
) -> Result<(), String> {
    // Validate duration: 0 (off) or up to 30 days
    const MAX_TIMER_SECS: u64 = 30 * 24 * 60 * 60; // 30 days
    if duration_secs > MAX_TIMER_SECS {
        return Err("Timer duration too long (max 30 days)".to_string());
    }

    let state = app.state::<AppState>();

    // Save setting to vault
    {
        let vault = state.vault.lock().unwrap();
        let settings = ConversationSettings {
            auto_delete_secs: duration_secs,
        };
        vault
            .write_file(&format!("conversations/{}.enc", device_id), &settings)
            .map_err(|e| e.to_string())?;
    }

    // Apply timer to existing messages
    {
        let history = state.history.lock().unwrap();
        if let Some(ref h) = *history {
            h.set_expires_for_peer(&device_id, duration_secs).ok();
        }
    }

    // Send control message to peer
    let ctrl = echo_client::wire::ControlMessage::SetTimer { duration_secs };
    let payload = echo_client::wire::encode_ctrl(&ctrl);
    send_encrypted_payload(&app, &device_id, &payload).await?;

    // Emit event locally
    app.emit(
        events::EVENT_TIMER_CHANGED,
        &serde_json::json!({
            "peer_id": device_id,
            "duration_secs": duration_secs,
        }),
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}

/// Get auto-delete timer setting for a conversation.
#[tauri::command]
pub fn get_auto_delete(app: AppHandle, device_id: String) -> Result<u64, String> {
    let state = app.state::<AppState>();
    let vault = state.vault.lock().unwrap();
    let settings: ConversationSettings = vault
        .read_file(&format!("conversations/{}.enc", device_id))
        .unwrap_or_default();
    Ok(settings.auto_delete_secs)
}

/// Edit a sent message. Updates locally and sends control message to peer.
#[tauri::command]
pub async fn edit_message(
    app: AppHandle,
    device_id: String,
    msg_id: String,
    new_text: String,
) -> Result<(), String> {
    // Input validation: reject empty or oversized edits
    let new_text = new_text.trim().to_string();
    if new_text.is_empty() {
        return Err("Edit text cannot be empty".to_string());
    }
    if new_text.len() > 10_000 {
        return Err("Edit text too long (max 10KB)".to_string());
    }

    let state = app.state::<AppState>();

    // Parse row_id and verify ownership via direct query (no 200-message load)
    let (row_id, timestamp) = {
        let history = state.history.lock().unwrap();
        let h = history.as_ref().ok_or("Not signed in")?;

        let rid: i64 = if let Some(stripped) = msg_id.strip_prefix("hist-") {
            stripped.parse().map_err(|_| "Invalid message ID".to_string())?
        } else {
            return Err("Invalid message ID format".to_string());
        };

        // Direct row query: get metadata without loading all messages
        let (sent_by_me, ts, _stored_msg_id) = h
            .get_message_info(rid)
            .map_err(|e| e.to_string())?
            .ok_or("Message not found")?;

        // CRITICAL: only allow editing your own messages
        if !sent_by_me {
            return Err("Cannot edit received messages".to_string());
        }

        (rid, ts)
    };

    // Send control message to peer FIRST — if this fails, local state stays unchanged
    let ctrl = echo_client::wire::ControlMessage::EditMessage {
        sender_msg_id: msg_id.clone(),
        original_timestamp: timestamp,
        new_text: new_text.clone(),
    };
    let payload = echo_client::wire::encode_ctrl(&ctrl);
    send_encrypted_payload(&app, &device_id, &payload).await?;

    // Network send succeeded — now update local history
    {
        let history = state.history.lock().unwrap();
        if let Some(ref h) = *history {
            h.edit_message(row_id, &device_id, &new_text)
                .map_err(|e| e.to_string())?;
        }
    }

    // Emit event locally
    app.emit(
        events::EVENT_MESSAGE_EDITED,
        &serde_json::json!({
            "peer_id": device_id,
            "msg_id": msg_id,
            "new_text": new_text,
        }),
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}

/// Delete a sent message. Removes locally and sends control message to peer.
#[tauri::command]
pub async fn delete_message_cmd(
    app: AppHandle,
    device_id: String,
    msg_id: String,
) -> Result<(), String> {
    let state = app.state::<AppState>();

    // Parse row_id and verify ownership via direct query
    let (row_id, timestamp) = {
        let history = state.history.lock().unwrap();
        let h = history.as_ref().ok_or("Not signed in")?;

        let rid: i64 = if let Some(stripped) = msg_id.strip_prefix("hist-") {
            stripped.parse().map_err(|_| "Invalid message ID".to_string())?
        } else {
            return Err("Invalid message ID format".to_string());
        };

        // Direct row query: get metadata without loading all messages
        let (sent_by_me, ts, _stored_msg_id) = h
            .get_message_info(rid)
            .map_err(|e| e.to_string())?
            .ok_or("Message not found")?;

        // CRITICAL: only allow deleting your own messages
        if !sent_by_me {
            return Err("Cannot delete received messages".to_string());
        }

        (rid, ts)
    };

    // Send control message to peer FIRST — if this fails, local state stays unchanged
    let ctrl = echo_client::wire::ControlMessage::DeleteMessage {
        sender_msg_id: msg_id.clone(),
        original_timestamp: timestamp,
    };
    let payload = echo_client::wire::encode_ctrl(&ctrl);
    send_encrypted_payload(&app, &device_id, &payload).await?;

    // Network send succeeded — now delete from local history
    {
        let history = state.history.lock().unwrap();
        if let Some(ref h) = *history {
            h.delete_message(row_id).map_err(|e| e.to_string())?;
        }
    }

    // Emit event locally
    app.emit(
        events::EVENT_MESSAGE_DELETED,
        &serde_json::json!({
            "peer_id": device_id,
            "msg_id": msg_id,
        }),
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}
