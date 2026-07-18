use std::time::Duration;

use tauri::{AppHandle, Emitter, Manager};
use tokio::time;

use base64::Engine as _;

use zeroize::Zeroize;

use echo_client::http::HttpClient;
use echo_client::identity::SessionMeta;
use echo_client::wire::WireMessage;
use echo_client::ws::{WsClient, WsInbound, WsOutbound};
use echo_crypto::ratchet::state::RatchetState;

use echo_client::wire::ConversationSettings;

use crate::commands::messaging::{build_media_text, media_dir};
use crate::events;
use crate::state::{AppState, ChatMessage, GroupChatMessage};

/// Start the background poller. Attempts WebSocket first, falls back to 3s polling.
pub fn start_poller(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut ws_backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(60);

        loop {
            let state = app.state::<AppState>();
            let signed_in = *state.signed_in.lock().unwrap();
            if !signed_in {
                time::sleep(Duration::from_secs(1)).await;
                ws_backoff = Duration::from_secs(1);
                continue;
            }

            // Try WebSocket connection
            let ws_result = try_ws_connect(&app).await;
            match ws_result {
                Ok((mut rx, ws_tx, handle)) => {
                    ws_backoff = Duration::from_secs(1);
                    // Store WS sender for typing indicators
                    *app.state::<AppState>().ws_tx.lock().unwrap() = Some(ws_tx);
                    emit_connection_state(&app, "live");

                    // WS message loop
                    let mut prekey_timer = time::interval(Duration::from_secs(30));
                    loop {
                        tokio::select! {
                            Some(inbound) = rx.recv() => {
                                match inbound {
                                    WsInbound::NewMessage { id, envelope, queued_at } => {
                                        let qm = echo_client::http::QueuedMessage {
                                            id,
                                            envelope,
                                            queued_at,
                                        };
                                        process_single_message(&app, &qm).await;
                                    }
                                    WsInbound::Typing { sender_device_id } => {
                                        app.emit(events::EVENT_TYPING, &sender_device_id.to_string()).ok();
                                    }
                                    WsInbound::Delivered { sender_device_id, up_to_timestamp } => {
                                        // A peer confirmed delivery of our messages
                                        let state = app.state::<AppState>();
                                        let peer = sender_device_id.to_string();
                                        {
                                            let history = state.history.lock().unwrap();
                                            if let Some(ref h) = *history {
                                                h.update_sent_status(&peer, up_to_timestamp as u64, 1).ok();
                                            }
                                        }
                                        app.emit(events::EVENT_DELIVERED, &serde_json::json!({
                                            "peer_id": peer,
                                            "up_to_timestamp": up_to_timestamp
                                        })).ok();
                                    }
                                    WsInbound::Read { sender_device_id, up_to_timestamp } => {
                                        // A peer confirmed they read our messages
                                        let state = app.state::<AppState>();
                                        let peer = sender_device_id.to_string();
                                        {
                                            let history = state.history.lock().unwrap();
                                            if let Some(ref h) = *history {
                                                h.update_sent_status(&peer, up_to_timestamp as u64, 2).ok();
                                            }
                                        }
                                        app.emit(events::EVENT_READ, &serde_json::json!({
                                            "peer_id": peer,
                                            "up_to_timestamp": up_to_timestamp
                                        })).ok();
                                    }
                                    WsInbound::Ping => {}
                                }
                            }
                            _ = prekey_timer.tick() => {
                                // Safety net: poll HTTP even in WS mode to catch missed messages
                                // (e.g. network switch, dead WS connection server hasn't detected)
                                if let Err(e) = poll_messages(&app).await {
                                    tracing::debug!("ws-mode safety poll failed: {}", e);
                                }
                                // Periodic prekey check, key rotation, outbox drain, group poll, and purge in WS mode
                                check_and_replenish_prekeys(&app).await;
                                check_and_rotate_keys(&app).await;
                                check_and_refresh_sender_cert(&app).await;
                                drain_outbox(&app).await;
                                poll_group_messages(&app).await;
                                purge_expired_messages(&app);
                            }
                            else => {
                                // WS channel closed
                                break;
                            }
                        }
                    }

                    handle.abort();
                    *app.state::<AppState>().ws_tx.lock().unwrap() = None;
                    tracing::info!("ws disconnected, falling back to polling");
                    emit_connection_state(&app, "polling");
                }
                Err(e) => {
                    tracing::debug!("ws connect failed: {}, polling", e);
                    emit_connection_state(&app, "polling");
                }
            }

            // Fallback: poll for a while, then retry WS
            let poll_rounds = (ws_backoff.as_secs() / 3).max(1);
            for _ in 0..poll_rounds {
                let state = app.state::<AppState>();
                let signed_in = *state.signed_in.lock().unwrap();
                if !signed_in {
                    break;
                }

                if let Err(e) = poll_messages(&app).await {
                    tracing::warn!("poll error: {}", e);
                }

                // Prekey check + key rotation + outbox drain + group poll + purge during polling too
                check_and_replenish_prekeys(&app).await;
                check_and_rotate_keys(&app).await;
                check_and_refresh_sender_cert(&app).await;
                drain_outbox(&app).await;
                poll_group_messages(&app).await;
                purge_expired_messages(&app);

                time::sleep(Duration::from_secs(3)).await;
            }

            // Exponential backoff for WS reconnect
            ws_backoff = (ws_backoff * 2).min(max_backoff);
        }
    });
}

fn emit_connection_state(app: &AppHandle, mode: &str) {
    app.emit(events::EVENT_CONNECTION_STATE, mode).ok();
}

/// Try to establish a WebSocket connection.
async fn try_ws_connect(
    app: &AppHandle,
) -> anyhow::Result<(
    tokio::sync::mpsc::Receiver<WsInbound>,
    tokio::sync::mpsc::Sender<WsOutbound>,
    tokio::task::JoinHandle<()>,
)> {
    let state = app.state::<AppState>();

    let (base_url, device_id, ed_private) = {
        let identity = state.identity.lock().unwrap();
        let identity_state = identity.as_ref().ok_or_else(|| anyhow::anyhow!("no identity"))?;
        let http = state.http.lock().unwrap();
        let http_ref = http.as_ref().ok_or_else(|| anyhow::anyhow!("no http"))?;
        let base_url = http_ref.base_url().to_string();
        let device_id = identity_state.device_id;
        let mut ed_bytes = [0u8; 32];
        ed_bytes.copy_from_slice(&identity_state.identity_ed_private);
        (base_url, device_id, ed_bytes)
    };

    let ws_client = WsClient::new(&base_url, device_id, &ed_private);
    ws_client.connect().await
}

/// Process a single queued message (shared by WS and poll paths).
async fn process_single_message(app: &AppHandle, qm: &echo_client::http::QueuedMessage) {
    let state = app.state::<AppState>();

    tracing::info!("▶ MSG #{} — begin processing (envelope len={})", qm.id, qm.envelope.len());

    let identity_state = {
        let id = state.identity.lock().unwrap();
        match id.as_ref() {
            Some(s) => s.clone(),
            None => {
                tracing::error!("▶ MSG #{} — NO IDENTITY STATE, dropping", qm.id);
                return;
            }
        }
    };

    tracing::info!("▶ MSG #{} — our device_id={}", qm.id, identity_state.device_id);
    let keys = identity_state.reconstruct_keys();

    let envelope_bytes = match hex::decode(&qm.envelope) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("▶ MSG #{} — FAIL hex decode: {}", qm.id, e);
            app.emit(events::EVENT_MESSAGE_ERROR, &format!("message {}: invalid envelope hex", qm.id)).ok();
            ack_single(app, qm.id).await;
            return;
        }
    };

    let envelope: echo_crypto::SealedEnvelope = match bincode::deserialize(&envelope_bytes) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("▶ MSG #{} — FAIL envelope deserialize: {}", qm.id, e);
            app.emit(events::EVENT_MESSAGE_ERROR, &format!("message {}: envelope deserialization failed", qm.id)).ok();
            ack_single(app, qm.id).await;
            return;
        }
    };

    // Load server transparency key for mandatory cert verification
    let mut server_pk: Option<[u8; 32]> = {
        let vault = state.vault.lock().unwrap();
        vault.load_server_transparency_key().and_then(|hex_str| {
            let bytes = hex::decode(&hex_str).ok()?;
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(arr)
            } else {
                None
            }
        })
    };

    // If transparency key is missing, fetch it from server before rejecting
    if server_pk.is_none() {
        tracing::info!("▶ MSG #{} — no cached transparency key, fetching from server...", qm.id);
        let http = {
            let h = state.http.lock().unwrap();
            h.as_ref().map(|http| {
                let mut ed_bytes = [0u8; 32];
                ed_bytes.copy_from_slice(&identity_state.identity_ed_private);
                HttpClient::with_auth(http.base_url(), identity_state.device_id, &ed_bytes)
            })
        };
        if let Some(http) = http {
            if let Ok(sth_resp) = http.fetch_sth().await {
                if let Ok(bytes) = hex::decode(&sth_resp.server_public_key) {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        server_pk = Some(arr);
                        let vault = state.vault.lock().unwrap();
                        vault.save_server_transparency_key(&sth_resp.server_public_key).ok();
                        vault.save_server_ml_dsa_key(&sth_resp.server_ml_dsa_public).ok();
                        tracing::info!("▶ MSG #{} — fetched and cached transparency key", qm.id);
                    }
                }
            }
        }
    }

    // H1: server transparency key is now REQUIRED for cert verification
    let server_pk = match server_pk {
        Some(pk) => pk,
        None => {
            tracing::error!("▶ MSG #{} — REJECT: no server transparency key available", qm.id);
            app.emit(events::EVENT_MESSAGE_ERROR, &format!("message {}: no server key for cert verification", qm.id)).ok();
            ack_single(app, qm.id).await;
            return;
        }
    };

    let server_ml_dsa_pk = {
        let vault = state.vault.lock().unwrap();
        hex::decode(vault.load_server_ml_dsa_key().unwrap_or_default()).unwrap_or_default()
    };
    let (sender_cert, inner) = match echo_crypto::sealed_sender::unseal_message(
        &keys.identity_dh,
        &envelope,
        &server_pk,
        &server_ml_dsa_pk,
    ) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("▶ MSG #{} — FAIL unseal: {:?}", qm.id, e);
            app.emit(events::EVENT_MESSAGE_ERROR, &format!("message {}: unseal/cert verification failed", qm.id)).ok();
            // ACK the message even on unseal failure to prevent infinite re-delivery loop.
            // If unseal fails it means the message was sealed to the wrong DH key or is corrupted;
            // retrying won't help.
            ack_single(app, qm.id).await;
            return;
        }
    };

    let sender_device_id = sender_cert.sender_device_id;
    let sender_uuid = uuid::Uuid::from_bytes(sender_device_id.0);

    tracing::info!("▶ MSG #{} — unsealed OK, sender={}", qm.id, sender_uuid);

    let wire_msg: WireMessage = match bincode::deserialize(&inner) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!("▶ MSG #{} — FAIL wire deserialize: {}", qm.id, e);
            app.emit(events::EVENT_MESSAGE_ERROR, &format!("message {}: wire message corrupted", qm.id)).ok();
            ack_single(app, qm.id).await;
            return;
        }
    };

    let is_prekey_msg = matches!(wire_msg, WireMessage::PreKey { .. });
    tracing::info!("▶ MSG #{} — wire type={}", qm.id, if is_prekey_msg { "PreKey" } else { "Normal" });

    let (header_bytes, encrypted_header, ciphertext, prekey_data) = match wire_msg {
        WireMessage::PreKey {
            sender_identity_key,
            sender_identity_dh_key,
            sender_identity_dh_signature,
            sender_ml_dsa_identity_key,
            sender_identity_dh_ml_dsa_signature,
            ephemeral_public,
            pq_ciphertext,
            used_one_time_prekey_id,
            ratchet_header,
            encrypted_header,
            ciphertext,
        } => (
            ratchet_header,
            encrypted_header,
            ciphertext,
            Some((sender_identity_key, sender_identity_dh_key, sender_identity_dh_signature, sender_ml_dsa_identity_key, sender_identity_dh_ml_dsa_signature, ephemeral_public, pq_ciphertext, used_one_time_prekey_id)),
        ),
        WireMessage::Normal {
            ratchet_header,
            encrypted_header,
            ciphertext,
        } => (ratchet_header, encrypted_header, ciphertext, None),
    };

    let header: echo_crypto::MessageHeader = match bincode::deserialize(&header_bytes) {
        Ok(h) => h,
        Err(_) => {
            app.emit(events::EVENT_MESSAGE_ERROR, &format!("message {}: header deserialization failed", qm.id)).ok();
            ack_single(app, qm.id).await;
            return;
        }
    };

    let enc_msg = echo_crypto::ratchet::session::EncryptedMessage {
        header,
        encrypted_header,
        ciphertext,
    };

    // Try existing session from vault
    let session_result: Option<(RatchetState, SessionMeta)> = {
        let vault = state.vault.lock().unwrap();
        vault.load_session(sender_uuid).ok()
    };

    tracing::info!(
        "▶ MSG #{} — existing session for {}? {}{}",
        qm.id, sender_uuid,
        if session_result.is_some() { "YES" } else { "NO" },
        session_result.as_ref().map(|(rs, meta)| format!(
            " [needs_prekey={}, send_chain={}, recv_chain={}, dh_num={}, send_n={}, recv_n={}]",
            meta.needs_prekey_message,
            rs.sending_chain_key.is_some(),
            rs.receiving_chain_key.is_some(),
            rs.dh_ratchet_number,
            rs.send_message_number,
            rs.recv_message_number
        )).unwrap_or_default()
    );

    let mut existing_session_handled = false;
    // Dual-initiator race tiebreaker: when both sides auto-established and sent
    // PreKey messages simultaneously, use device ID comparison to pick one session.
    // The side with the higher device ID "wins" — their initiator session is kept.
    // The "loser" replaces their session with a responder from the winner's PreKey.
    let mut skip_session_save = false;

    if let Some((ratchet_state, existing_meta)) = session_result {
        let mut session = echo_crypto::ratchet::TripleRatchetSession::new(ratchet_state);
        tracing::info!("▶ MSG #{} — attempting decrypt with existing session...", qm.id);
        match session.decrypt(&enc_msg) {
        Ok(decrypted) => {
            tracing::info!("▶ MSG #{} — ✓ DECRYPT OK with existing session (plaintext len={})", qm.id, decrypted.plaintext.len());
            existing_session_handled = true;
            {
                let vault = state.vault.lock().unwrap();
                if vault.update_session(sender_uuid, session.export_state()).is_err() {
                    tracing::warn!("failed to persist ratchet for {}, skipping ack", sender_uuid);
                    return;
                }
            }
            ack_single(app, qm.id).await;

            // Check if this is a sender key distribution (group key setup)
            if let Some(skd) = echo_client::wire::decode_skd(&decrypted.plaintext) {
                process_sender_key_distribution(app, &skd);
                return;
            }

            // Check if this is a control message (auto-delete, edit, delete)
            if let Some(ctrl) = echo_client::wire::decode_ctrl(&decrypted.plaintext) {
                process_control_message(app, &sender_uuid.to_string(), ctrl);
                return;
            }

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg_id = format!("{}-{}", sender_uuid, qm.id);

            let (history_text, display_text, media_url, media_mime, media_filename) =
                decode_media_payload(&decrypted.plaintext, &sender_uuid.to_string(), now);

            // Check conversation timer for auto-delete expiry
            let expires_at = {
                let vault = state.vault.lock().unwrap();
                let settings: ConversationSettings = vault
                    .read_file(&format!("conversations/{}.enc", sender_uuid))
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
                    h.insert_message_with_expiry(&msg_id, &sender_uuid.to_string(), &history_text, false, now, expires_at).ok();
                }
            }

            let chat_msg = ChatMessage {
                id: msg_id,
                from_device: sender_uuid.to_string(),
                text: display_text,
                sent_by_me: false,
                timestamp: now,
                status: 0,
                edited: false,
                media_url,
                media_mime,
                media_filename,
            };
            app.emit(events::EVENT_NEW_MESSAGE, &chat_msg).ok();

            // Send delivery receipt via WS
            send_delivery_receipt(app, sender_uuid, now);
        }
        Err(e) => {
            tracing::warn!("▶ MSG #{} — ✗ DECRYPT FAILED with existing session: {}", qm.id, e);
            if prekey_data.is_some() {
                // Check for dual-initiator race: we already sent using our session
                let we_already_sent = !existing_meta.needs_prekey_message;
                tracing::info!("▶ MSG #{} — PreKey msg + existing session: we_already_sent={}, our_id={}, sender_id={}", qm.id, we_already_sent, identity_state.device_id, sender_uuid);
                if we_already_sent {
                    // Both sides established independently and sent PreKey messages.
                    // Use device ID as deterministic tiebreaker: higher UUID wins.
                    let our_device_id = identity_state.device_id;
                    if our_device_id > sender_uuid {
                        // We "win": decrypt this message with a temp responder session,
                        // but keep our initiator session. The sender will receive our
                        // PreKey and adopt our session as responder.
                        tracing::warn!(
                            "dual-initiator race with {} — we win (higher device_id {}), \
                             processing message without session replacement",
                            sender_uuid, our_device_id
                        );
                        skip_session_save = true;
                    } else {
                        tracing::warn!(
                            "dual-initiator race with {} — they win (higher device_id), \
                             replacing our session",
                            sender_uuid
                        );
                    }
                } else {
                    tracing::warn!(
                        "decrypt failed with existing session for {} but PreKey data present \
                         -- replacing session (race condition recovery)",
                        sender_uuid
                    );
                }
            } else {
                existing_session_handled = true;
                tracing::error!("decrypt failed for msg {} from {}: {}", qm.id, sender_uuid, e);
                app.emit(events::EVENT_MESSAGE_ERROR, &format!("message {}: decrypt failed: {}", qm.id, e)).ok();
            }
        }
        }
    }

    if !existing_session_handled {
    tracing::info!("▶ MSG #{} — existing session NOT handled, prekey_data present={}", qm.id, prekey_data.is_some());
    if let Some((sender_ik, sender_dh_key, sender_dh_sig, sender_ml_dsa_ik, sender_dh_ml_dsa_sig, ephemeral_pub, pq_ct, otpk_id)) = prekey_data {
        tracing::info!("▶ MSG #{} — creating RESPONDER session via X4DH (otpk_id={:?})", qm.id, otpk_id);
        let mut eph = [0u8; 32];
        eph.copy_from_slice(&ephemeral_pub);
        let mut sdk = [0u8; 32];
        sdk.copy_from_slice(&sender_dh_key);

        // C4: Reconstruct Alice's Ed25519 identity for DH key binding verification
        let sender_ed_key = if sender_ik.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&sender_ik);
            Some(echo_crypto::IdentityPublicKey(arr))
        } else {
            None
        };
        let sender_dh_sig_ref = if sender_dh_sig.is_empty() { None } else { Some(sender_dh_sig.as_slice()) };
        let sender_ml_dsa_ref = if sender_ml_dsa_ik.is_empty() { None } else { Some(sender_ml_dsa_ik.as_slice()) };
        let sender_dh_ml_dsa_sig_ref = if sender_dh_ml_dsa_sig.is_empty() { None } else { Some(sender_dh_ml_dsa_sig.as_slice()) };

        let otp_keypair = otpk_id.and_then(|id| {
            keys.one_time_prekeys.iter().find(|(kid, _)| *kid == id).map(|(_, kp)| kp)
        });

        let x4dh_result = match echo_crypto::ratchet::x4dh::X4DH::respond(
            &keys.identity_ed,
            &keys.identity_dh,
            &keys.signed_prekey,
            otp_keypair,
            &keys.pq_sk,
            &echo_crypto::PublicKey(sdk),
            sender_ed_key.as_ref(),
            sender_dh_sig_ref,
            sender_ml_dsa_ref,
            sender_dh_ml_dsa_sig_ref,
            &echo_crypto::PublicKey(eph),
            &echo_crypto::PqCiphertext(pq_ct.clone()),
        ) {
            Ok(r) => {
                tracing::info!("▶ MSG #{} — X4DH respond OK", qm.id);
                r
            },
            Err(e) => {
                tracing::error!("▶ MSG #{} — FAIL X4DH respond: {:?}", qm.id, e);
                return;
            }
        };

        let mut sik = [0u8; 32];
        sik.copy_from_slice(&sender_ik);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let ratchet_state = echo_crypto::ratchet::state::RatchetState {
            local_identity: keys.identity_ed.public_key(),
            remote_identity: echo_crypto::IdentityPublicKey(sik),
            epoch_number: 0,
            // Bug #2 fix (Jun 27): the responder's initial epoch keypair MUST be its X4DH
            // PQ prekey — that is the key the initiator encapsulates its first epoch ratchet
            // to (initiator's peer_epoch_pk = bundle.pq_prekey). Leaving these None made the
            // responder unable to decapsulate the first epoch ratchet (100-msg / 24h), so
            // messages silently dropped after time passed.
            my_epoch_pk: Some(echo_crypto::PqPublicKey(identity_state.pq_pk.clone())),
            my_epoch_sk: Some(keys.pq_sk.clone()),
            peer_epoch_pk: None, // learns the initiator's epoch key from their first epoch update
            epoch_message_count: 0,
            epoch_start_time: now,
            pending_epoch: None,
            dh_ratchet_number: 0,
            my_dh_public: keys.signed_prekey.public_key(),
            my_dh_private: Some(keys.signed_prekey.private_key_bytes()),
            peer_dh_public: Some(enc_msg.header.dh_public.clone()),
            root_key: x4dh_result.root_key.clone(),
            sending_chain_key: None,
            receiving_chain_key: Some(x4dh_result.chain_key),
            send_message_number: 0,
            recv_message_number: 0,
            prev_sending_chain_length: 0,
            sending_header_key: Some(echo_crypto::crypto::kdf::derive_header_key(&x4dh_result.root_key, false)),
            receiving_header_key: Some(echo_crypto::crypto::kdf::derive_header_key(&x4dh_result.root_key, true)),
            next_sending_header_key: Some(echo_crypto::crypto::kdf::derive_header_key(&x4dh_result.root_key, false)),
            next_receiving_header_key: Some(echo_crypto::crypto::kdf::derive_header_key(&x4dh_result.root_key, true)),
            skipped_keys: std::collections::HashMap::new(),
            processed_ids: std::collections::HashSet::new(),
            processed_order: std::collections::VecDeque::new(),
        };

        let meta = SessionMeta {
            recipient_device_id: sender_uuid,
            recipient_identity_key: sender_ik.clone(),
            recipient_dh_key: echo_crypto::PublicKey(sdk),
            ephemeral_public: ephemeral_pub,
            pq_ciphertext: pq_ct,
            used_one_time_prekey_id: None,
            needs_prekey_message: false, // Responder: session established via recv, never send PreKey
        };

        let mut session = echo_crypto::ratchet::TripleRatchetSession::new(ratchet_state);
        tracing::info!("▶ MSG #{} — attempting decrypt with NEW responder session (skip_save={})...", qm.id, skip_session_save);
        match session.decrypt(&enc_msg) {
            Ok(decrypted) => {
            tracing::info!("▶ MSG #{} — ✓ DECRYPT OK with responder session (plaintext len={})", qm.id, decrypted.plaintext.len());
            if !skip_session_save {
                let vault = state.vault.lock().unwrap();
                if vault.save_session(sender_uuid, session.export_state(), &meta).is_err() {
                    tracing::warn!("failed to persist new session for {}, skipping ack", sender_uuid);
                    return;
                }
            } else {
                tracing::info!("dual-initiator winner: decrypted message from {} without saving responder session", sender_uuid);
            }
            ack_single(app, qm.id).await;
            if !skip_session_save {
                app.emit(events::EVENT_SESSION_ESTABLISHED, &sender_uuid.to_string()).ok();
            }

            // Check if this is a sender key distribution (group key setup)
            if let Some(skd) = echo_client::wire::decode_skd(&decrypted.plaintext) {
                process_sender_key_distribution(app, &skd);
                return;
            }

            // Check if this is a control message (auto-delete, edit, delete)
            if let Some(ctrl) = echo_client::wire::decode_ctrl(&decrypted.plaintext) {
                process_control_message(app, &sender_uuid.to_string(), ctrl);
                return;
            }

            let msg_id = format!("{}-{}", sender_uuid, qm.id);

            let (history_text, display_text, media_url, media_mime, media_filename) =
                decode_media_payload(&decrypted.plaintext, &sender_uuid.to_string(), now);

            // Check conversation timer for auto-delete expiry
            let expires_at = {
                let vault = state.vault.lock().unwrap();
                let settings: ConversationSettings = vault
                    .read_file(&format!("conversations/{}.enc", sender_uuid))
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
                    h.insert_message_with_expiry(&msg_id, &sender_uuid.to_string(), &history_text, false, now, expires_at).ok();
                }
            }

            let chat_msg = ChatMessage {
                id: msg_id,
                from_device: sender_uuid.to_string(),
                text: display_text,
                sent_by_me: false,
                timestamp: now,
                status: 0,
                edited: false,
                media_url,
                media_mime,
                media_filename,
            };
            app.emit(events::EVENT_NEW_MESSAGE, &chat_msg).ok();

            // Send delivery receipt via WS
            send_delivery_receipt(app, sender_uuid, now);
            }
            Err(e) => {
                tracing::error!("▶ MSG #{} — ✗ DECRYPT FAILED with responder session: {}", qm.id, e);
                app.emit(events::EVENT_MESSAGE_ERROR, &format!("message {}: new session decrypt failed: {}", qm.id, e)).ok();
            }
        }
    } else {
        tracing::error!("▶ MSG #{} — NO PREKEY DATA and no existing session — cannot process (Normal msg with no session!)", qm.id);
    }
    }
}

/// Decode decrypted plaintext: detect media content, save to disk, return display info.
fn decode_media_payload(
    plaintext: &[u8],
    peer_id: &str,
    timestamp: u64,
) -> (String, String, Option<String>, Option<String>, Option<String>) {
    if let Some(media) = echo_client::wire::MediaContent::decode(plaintext) {
        // Save to disk
        let peer_dir = media_dir().join(peer_id);
        std::fs::create_dir_all(&peer_dir).ok();
        let safe_name: String = media.filename
            .replace(['/', '\\', '\0', ':', '<', '>', '|', '"', '?', '*'], "_")
            .replace("..", "_");
        let safe_name = safe_name.trim_matches(|c: char| c == '.' || c == ' ' || c == '_').to_string();
        let safe_name = if safe_name.is_empty() { "file".to_string() } else { safe_name };

        // MIME allowlist with canonical extensions. The on-disk extension is
        // forced to match the claimed MIME type so a spoofed filename (e.g.
        // "invoice.exe" claiming image/png) can never land on disk with an
        // executable extension. Unknown MIME types are quarantined as .bin.
        const ALLOWED_MIME_TYPES: &[(&str, &[&str])] = &[
            ("image/png", &["png"]),
            ("image/jpeg", &["jpg", "jpeg"]),
            ("image/gif", &["gif"]),
            ("image/webp", &["webp"]),
            ("audio/mpeg", &["mp3"]),
            ("audio/ogg", &["ogg"]),
            ("audio/wav", &["wav"]),
            ("video/mp4", &["mp4"]),
            ("video/webm", &["webm"]),
            ("application/pdf", &["pdf"]),
        ];
        let allowed = ALLOWED_MIME_TYPES
            .iter()
            .find(|(m, _)| *m == media.mime_type.as_str());
        let current_ext = safe_name.rsplit('.').next().map(|e| e.to_ascii_lowercase());
        let safe_name = match allowed {
            Some((_, exts)) if current_ext.as_deref().is_some_and(|e| exts.contains(&e)) => {
                safe_name
            }
            Some((_, exts)) => format!("{}.{}", safe_name, exts[0]),
            None => format!("{}.bin", safe_name),
        };
        let local_path = peer_dir.join(format!("{}_{}", timestamp, safe_name));
        std::fs::write(&local_path, &media.data).ok();

        let history_text =
            build_media_text(&media.mime_type, &media.filename, &local_path.to_string_lossy());

        // Build data URL for immediate display
        let b64 = base64::engine::general_purpose::STANDARD.encode(&media.data);
        let safe_mime = if allowed.is_some() {
            media.mime_type.clone()
        } else {
            "application/octet-stream".to_string()
        };
        let data_url = format!("data:{};base64,{}", safe_mime, b64);

        (
            history_text,
            media.filename.clone(),
            Some(data_url),
            Some(safe_mime),
            Some(media.filename),
        )
    } else {
        let text = String::from_utf8_lossy(plaintext).to_string();
        (text.clone(), text, None, None, None)
    }
}

/// Send a delivery receipt to the sender via WS, falling back to HTTP.
fn send_delivery_receipt(app: &AppHandle, sender: uuid::Uuid, timestamp: u64) {
    let state = app.state::<AppState>();
    let ws_tx = {
        let tx = state.ws_tx.lock().unwrap();
        tx.clone()
    };
    if let Some(tx) = ws_tx {
        // Try WS first
        if tx.try_send(WsOutbound::Delivered {
            recipient_device_id: sender.to_string(),
            up_to_timestamp: timestamp as i64,
        }).is_ok() {
            return;
        }
    }
    // Fallback: send via HTTP
    let app_handle = app.clone();
    tokio::spawn(async move {
        let state = app_handle.state::<AppState>();
        let http = {
            let identity = state.identity.lock().unwrap();
            let id_state = match identity.as_ref() {
                Some(s) => s.clone(),
                None => return,
            };
            let h = state.http.lock().unwrap();
            match h.as_ref() {
                Some(http) => {
                    let mut ed_bytes = [0u8; 32];
                    ed_bytes.copy_from_slice(&id_state.identity_ed_private);
                    echo_client::http::HttpClient::with_auth(
                        http.base_url(),
                        id_state.device_id,
                        &ed_bytes,
                    )
                }
                None => return,
            }
        };
        let _ = http.send_delivery_receipt(sender, timestamp as i64).await;
    });
}

/// Ack a single message.
async fn ack_single(app: &AppHandle, msg_id: i64) {
    let state = app.state::<AppState>();
    let (device_id, http) = {
        let identity = state.identity.lock().unwrap();
        let identity_state = match identity.as_ref() {
            Some(s) => s.clone(),
            None => return,
        };
        let h = state.http.lock().unwrap();
        match h.as_ref() {
            Some(http) => {
                let mut ed_bytes = [0u8; 32];
                ed_bytes.copy_from_slice(&identity_state.identity_ed_private);
                (identity_state.device_id, HttpClient::with_auth(http.base_url(), identity_state.device_id, &ed_bytes))
            }
            None => return,
        }
    };
    http.ack_messages(device_id, &[msg_id]).await.ok();
}

/// Poll-based message fetching (fallback when WS is not available).
async fn poll_messages(app: &AppHandle) -> anyhow::Result<()> {
    let state = app.state::<AppState>();

    let (device_id, identity_state) = {
        let id = state.identity.lock().unwrap();
        match id.as_ref() {
            Some(s) => (s.device_id, s.clone()),
            None => return Ok(()),
        }
    };

    let http = {
        let h = state.http.lock().unwrap();
        match h.as_ref() {
            Some(http) => {
                let mut ed_bytes = [0u8; 32];
                ed_bytes.copy_from_slice(&identity_state.identity_ed_private);
                HttpClient::with_auth(http.base_url(), device_id, &ed_bytes)
            }
            None => return Ok(()),
        }
    };

    let messages = http.receive_messages(device_id).await?;
    if messages.is_empty() {
        return Ok(());
    }

    for qm in &messages {
        process_single_message(app, qm).await;
    }

    Ok(())
}

/// Check one-time prekey count and replenish if low (Phase 3).
async fn check_and_replenish_prekeys(app: &AppHandle) {
    let state = app.state::<AppState>();

    let (device_id, identity_state) = {
        let id = state.identity.lock().unwrap();
        match id.as_ref() {
            Some(s) => (s.device_id, s.clone()),
            None => return,
        }
    };

    let http = {
        let h = state.http.lock().unwrap();
        match h.as_ref() {
            Some(http) => {
                let mut ed_bytes = [0u8; 32];
                ed_bytes.copy_from_slice(&identity_state.identity_ed_private);
                HttpClient::with_auth(http.base_url(), device_id, &ed_bytes)
            }
            None => return,
        }
    };

    let count = match http.prekey_count().await {
        Ok(c) => c,
        Err(_) => return,
    };

    if count >= 25 {
        return;
    }

    tracing::info!("prekey count low ({}), replenishing...", count);

    // Determine next_prekey_id from identity state
    let next_id = identity_state
        .one_time_prekeys
        .iter()
        .map(|(id, _)| *id)
        .max()
        .unwrap_or(100) + 1;

    let new_prekeys = echo_client::identity::KeyMaterial::generate_additional_prekeys(next_id, 100);

    // Build upload payload
    let otpks: Vec<(u32, String)> = new_prekeys
        .iter()
        .map(|(id, kp)| (*id, hex::encode(&kp.public_key().0)))
        .collect();

    if let Err(e) = http.upload_additional_otps(&otpks).await {
        tracing::warn!("failed to upload additional prekeys: {}", e);
        return;
    }

    // Save private keys to vault
    {
        let mut id_guard = state.identity.lock().unwrap();
        if let Some(ref mut id_state) = *id_guard {
            for (kid, kp) in &new_prekeys {
                id_state
                    .one_time_prekeys
                    .push((*kid, kp.private_key_bytes().0.to_vec()));
            }
            let vault = state.vault.lock().unwrap();
            vault.write_file("identity.enc", id_state).ok();
        }
    }

    tracing::info!("replenished 100 prekeys starting from id {}", next_id);
}

/// Check if keys need rotation (Phase 4).
async fn check_and_rotate_keys(app: &AppHandle) {
    let state = app.state::<AppState>();

    let identity_state = {
        let id = state.identity.lock().unwrap();
        match id.as_ref() {
            Some(s) => s.clone(),
            None => return,
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let last_rotation = identity_state.last_rotation_time.unwrap_or(0);
    let seven_days = 7 * 24 * 60 * 60;

    if last_rotation > 0 && (now - last_rotation) < seven_days {
        return;
    }

    // Skip on first run if we just created the account (last_rotation == 0 and keys are fresh)
    if last_rotation == 0 && identity_state.signed_prekey_id <= 1 {
        // Mark current time as last rotation so we start the 7-day clock
        let mut id_guard = state.identity.lock().unwrap();
        if let Some(ref mut id_state) = *id_guard {
            id_state.last_rotation_time = Some(now);
            let vault = state.vault.lock().unwrap();
            vault.write_file("identity.enc", id_state).ok();
        }
        return;
    }

    tracing::info!("rotating signed prekey and PQ prekey...");

    let keys = identity_state.reconstruct_keys();

    // Generate new signed prekey
    let new_spk_id = identity_state.signed_prekey_id + 1;
    let (new_spk, new_spk_sig) = echo_client::identity::KeyMaterial::rotate_signed_prekey(
        &keys.identity_ed,
        new_spk_id,
    );

    // Generate new PQ prekey
    let new_pq_id = identity_state.pq_prekey_id + 1;
    let (new_pq_pk, new_pq_sk, new_pq_sig) = echo_client::identity::KeyMaterial::rotate_pq_prekey(
        &keys.identity_ed,
        new_pq_id,
    );

    // Upload via existing upload_prekeys (server UPSERT handles it)
    let http = {
        let h = state.http.lock().unwrap();
        match h.as_ref() {
            Some(http) => {
                let mut ed_bytes = [0u8; 32];
                ed_bytes.copy_from_slice(&identity_state.identity_ed_private);
                HttpClient::with_auth(http.base_url(), identity_state.device_id, &ed_bytes)
            }
            None => return,
        }
    };

    // Build a KeyMaterial with new keys for upload
    let upload_keys = echo_client::identity::KeyMaterial {
        identity_ed: keys.identity_ed,
        identity_mldsa_pk: keys.identity_mldsa_pk,
        identity_mldsa_sk: keys.identity_mldsa_sk,
        identity_dh: keys.identity_dh,
        signed_prekey: new_spk,
        signed_prekey_id: new_spk_id,
        signed_prekey_sig: new_spk_sig,
        pq_pk: new_pq_pk,
        pq_sk: new_pq_sk.clone(),
        pq_prekey_id: new_pq_id,
        pq_prekey_sig: new_pq_sig,
        one_time_prekeys: vec![], // Don't re-upload OTPs during rotation
    };

    if let Err(e) = http
        .upload_prekeys(identity_state.account_id, &upload_keys, None)
        .await
    {
        tracing::warn!("key rotation upload failed: {}", e);
        return;
    }

    // Update identity state with new keys, stash old ones as grace period
    let grace_expiry = now + 14 * 24 * 60 * 60; // 14 days

    {
        let mut id_guard = state.identity.lock().unwrap();
        if let Some(ref mut id_state) = *id_guard {
            // Stash current keys as previous
            id_state.prev_signed_prekey_private = Some(id_state.signed_prekey_private.clone());
            id_state.prev_signed_prekey_id = Some(id_state.signed_prekey_id);
            id_state.prev_pq_sk = Some(id_state.pq_sk.clone());
            id_state.prev_pq_prekey_id = Some(id_state.pq_prekey_id);
            id_state.prev_key_expiry = Some(grace_expiry);

            // Set new keys
            id_state.signed_prekey_private = upload_keys.signed_prekey.private_key_bytes().0.to_vec();
            id_state.signed_prekey_public = upload_keys.signed_prekey.public_key().0.to_vec();
            id_state.signed_prekey_id = new_spk_id;
            id_state.pq_pk = upload_keys.pq_pk.0.clone();
            id_state.pq_sk = new_pq_sk.0.clone();
            id_state.pq_prekey_id = new_pq_id;
            id_state.last_rotation_time = Some(now);

            let vault = state.vault.lock().unwrap();
            vault.write_file("identity.enc", id_state).ok();
        }
    }

    tracing::info!("key rotation complete: spk_id={}, pq_id={}", new_spk_id, new_pq_id);
}

/// Bug #1 fix (Jun 27): the server-signed sender certificate expires 24h after it is issued
/// (server keys.rs sets expiry = now + 86400). It was only ever saved at registration; the
/// 7-day key rotation re-fetched a fresh cert but discarded it. So after a day the cached
/// cert was expired, recipients rejected every sealed message (verify_sender_cert), and
/// messages silently vanished. Refresh proactively whenever the cached cert is missing or
/// within 6h of expiry by re-fetching from the server and saving the new cert.
async fn check_and_refresh_sender_cert(app: &AppHandle) {
    let state = app.state::<AppState>();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Cheap gate: only hit the network when the cert is missing or near expiry.
    let needs_refresh = {
        let vault = state.vault.lock().unwrap();
        match vault.load_sender_cert::<echo_crypto::sealed_sender::SenderCertificate>() {
            Some(cert) => cert.expiry <= now + 6 * 60 * 60,
            None => true,
        }
    };
    if !needs_refresh {
        return;
    }

    let identity_state = {
        let id = state.identity.lock().unwrap();
        match id.as_ref() {
            Some(s) => s.clone(),
            None => return,
        }
    };

    let http = {
        let h = state.http.lock().unwrap();
        match h.as_ref() {
            Some(http) => {
                let mut ed_bytes = [0u8; 32];
                ed_bytes.copy_from_slice(&identity_state.identity_ed_private);
                HttpClient::with_auth(http.base_url(), identity_state.device_id, &ed_bytes)
            }
            None => return,
        }
    };

    // Re-upload the CURRENT keys (no rotation, no OTPs) purely to obtain a fresh cert.
    // Ed25519 signatures are deterministic, so re-signing reproduces the published sigs.
    let keys = identity_state.reconstruct_keys();
    let signed_prekey_sig = keys.identity_ed.sign(&keys.signed_prekey.public_key().0);
    let pq_pk = echo_crypto::PqPublicKey(identity_state.pq_pk.clone());
    let pq_prekey_sig = keys.identity_ed.sign(&pq_pk.0);

    let upload_keys = echo_client::identity::KeyMaterial {
        identity_ed: keys.identity_ed,
        identity_mldsa_pk: keys.identity_mldsa_pk,
        identity_mldsa_sk: keys.identity_mldsa_sk,
        identity_dh: keys.identity_dh,
        signed_prekey: keys.signed_prekey,
        signed_prekey_id: identity_state.signed_prekey_id,
        signed_prekey_sig,
        pq_pk,
        pq_sk: keys.pq_sk,
        pq_prekey_id: identity_state.pq_prekey_id,
        pq_prekey_sig,
        one_time_prekeys: vec![],
    };

    let cert_bytes = match http
        .upload_prekeys(identity_state.account_id, &upload_keys, None)
        .await
    {
        Ok((_, Some(cert_bytes), _, _)) => cert_bytes,
        Ok((_, None, _, _)) => {
            tracing::warn!("sender cert refresh: server returned no certificate");
            return;
        }
        Err(e) => {
            tracing::warn!("sender cert refresh upload failed: {}", e);
            return;
        }
    };

    // Counter-sign (C1) and save the fresh cert to the vault.
    match bincode::deserialize::<echo_crypto::sealed_sender::SenderCertificate>(&cert_bytes) {
        Ok(mut cert) => {
            let mut ed_priv = [0u8; 32];
            ed_priv.copy_from_slice(&identity_state.identity_ed_private);
            echo_crypto::sealed_sender::countersign_sender_cert(&mut cert, &ed_priv, &identity_state.identity_mldsa_private);
            ed_priv.zeroize();
            let vault = state.vault.lock().unwrap();
            if vault.save_sender_cert(&cert).is_err() {
                tracing::warn!("sender cert refresh: failed to save");
            } else {
                tracing::info!("sender cert refreshed (new expiry {})", cert.expiry);
            }
        }
        Err(e) => tracing::warn!("sender cert refresh: deserialize failed: {}", e),
    }
}

/// Drain outbox — attempt to send queued messages.
async fn drain_outbox(app: &AppHandle) {
    let state = app.state::<AppState>();

    let entries = {
        let outbox = state.outbox.lock().unwrap();
        match outbox.as_ref() {
            Some(ob) => match ob.pending_messages() {
                Ok(e) => e,
                Err(_) => return,
            },
            None => return,
        }
    };

    if entries.is_empty() {
        return;
    }

    let identity_state = {
        let id = state.identity.lock().unwrap();
        match id.as_ref() {
            Some(s) => s.clone(),
            None => return,
        }
    };

    let http = {
        let h = state.http.lock().unwrap();
        match h.as_ref() {
            Some(http) => {
                let mut ed_bytes = [0u8; 32];
                ed_bytes.copy_from_slice(&identity_state.identity_ed_private);
                HttpClient::with_auth(http.base_url(), identity_state.device_id, &ed_bytes)
            }
            None => return,
        }
    };

    for entry in &entries {
        let recipient: uuid::Uuid = match entry.recipient_device_id.parse() {
            Ok(u) => u,
            Err(_) => continue,
        };

        match http.send_message(recipient, &entry.envelope).await {
            Ok(()) => {
                // Remove from outbox
                {
                    let outbox = state.outbox.lock().unwrap();
                    if let Some(ref ob) = *outbox {
                        ob.mark_sent(entry.id).ok();
                    }
                }

                // Update history status from queued (3) → sent (0)
                {
                    let history = state.history.lock().unwrap();
                    if let Some(ref h) = *history {
                        h.set_message_status(&entry.msg_id, 0).ok();
                    }
                }

                // Notify frontend
                app.emit(events::EVENT_MESSAGE_SENT, &serde_json::json!({
                    "msg_id": entry.msg_id,
                    "peer_id": entry.recipient_device_id,
                })).ok();

                tracing::info!("outbox: sent queued message {} to {}", entry.msg_id, entry.recipient_device_id);
            }
            Err(_) => {
                // Still offline — stop trying (will retry next cycle)
                break;
            }
        }
    }
}

/// Process a sender key distribution received via pairwise session.
fn process_sender_key_distribution(
    app: &AppHandle,
    skd: &echo_crypto::group::SenderKeyDistribution,
) {
    let state = app.state::<AppState>();
    let group_id_str = uuid::Uuid::from_bytes(skd.group_id).to_string();

    let vault = state.vault.lock().unwrap();

    // Load or create a group session for this group
    let mut session = match vault.load_group_session(&group_id_str) {
        Some(s) => s,
        None => {
            // We received a sender key but don't have a session yet.
            // Create one — we'll get our own device id from identity state.
            let device_id = {
                let id = state.identity.lock().unwrap();
                match id.as_ref() {
                    Some(s) => {
                        let bytes = s.device_id.as_bytes();
                        echo_crypto::types::DeviceId(*bytes)
                    }
                    None => return,
                }
            };
            echo_crypto::group::GroupSession::new(skd.group_id, device_id)
        }
    };

    session.process_sender_key(skd);

    vault.save_group_session(&group_id_str, &session).ok();

    tracing::info!(
        "processed sender key from {:?} for group {}",
        skd.sender_device,
        group_id_str
    );
}

/// Process a control message received from a peer.
fn process_control_message(
    app: &AppHandle,
    sender_uuid_str: &str,
    ctrl: echo_client::wire::ControlMessage,
) {
    let state = app.state::<AppState>();

    match ctrl {
        echo_client::wire::ControlMessage::SessionInit => {
            // Session init: X4DH was already processed from the PreKey wrapper.
            // Nothing to do here — session is established, green dot will show.
            tracing::info!("session init control message from {} — session established", sender_uuid_str);
        }
        echo_client::wire::ControlMessage::SetTimer { duration_secs } => {
            // Validate: reject absurd timer values (max 30 days)
            const MAX_TIMER_SECS: u64 = 30 * 24 * 60 * 60;
            if duration_secs > MAX_TIMER_SECS {
                tracing::warn!(
                    "rejecting SetTimer from {} with duration {}s (max {})",
                    sender_uuid_str, duration_secs, MAX_TIMER_SECS
                );
                return;
            }

            // Save setting to vault
            {
                let vault = state.vault.lock().unwrap();
                let settings = ConversationSettings {
                    auto_delete_secs: duration_secs,
                };
                vault
                    .write_file(
                        &format!("conversations/{}.enc", sender_uuid_str),
                        &settings,
                    )
                    .ok();
            }

            // Apply timer to existing messages
            {
                let history = state.history.lock().unwrap();
                if let Some(ref h) = *history {
                    h.set_expires_for_peer(sender_uuid_str, duration_secs).ok();
                }
            }

            app.emit(
                events::EVENT_TIMER_CHANGED,
                &serde_json::json!({
                    "peer_id": sender_uuid_str,
                    "duration_secs": duration_secs,
                }),
            )
            .ok();

            tracing::info!(
                "timer set to {}s for conversation with {}",
                duration_secs,
                sender_uuid_str
            );
        }
        echo_client::wire::ControlMessage::EditMessage {
            sender_msg_id: _,
            original_timestamp,
            new_text,
        } => {
            // Validate: reject oversized edit text (max 10KB)
            if new_text.len() > 10_000 {
                tracing::warn!(
                    "rejecting EditMessage from {} with text length {} (max 10000)",
                    sender_uuid_str, new_text.len()
                );
                return;
            }

            let history = state.history.lock().unwrap();
            if let Some(ref h) = *history {
                // Find message by peer + approximate timestamp (receiver stored it as received)
                if let Ok(Some(row_id)) =
                    h.find_message_by_peer_and_time(sender_uuid_str, false, original_timestamp)
                {
                    h.edit_message(row_id, sender_uuid_str, &new_text).ok();
                    let msg_id = h.get_msg_id(row_id).ok().flatten().unwrap_or_default();
                    app.emit(
                        events::EVENT_MESSAGE_EDITED,
                        &serde_json::json!({
                            "peer_id": sender_uuid_str,
                            "msg_id": msg_id,
                            "new_text": new_text,
                        }),
                    )
                    .ok();
                    tracing::info!("edited message {} from {}", row_id, sender_uuid_str);
                }
            }
        }
        echo_client::wire::ControlMessage::DeleteMessage {
            sender_msg_id: _,
            original_timestamp,
        } => {
            let history = state.history.lock().unwrap();
            if let Some(ref h) = *history {
                if let Ok(Some(row_id)) =
                    h.find_message_by_peer_and_time(sender_uuid_str, false, original_timestamp)
                {
                    let msg_id = h.get_msg_id(row_id).ok().flatten().unwrap_or_default();
                    h.delete_message(row_id).ok();
                    app.emit(
                        events::EVENT_MESSAGE_DELETED,
                        &serde_json::json!({
                            "peer_id": sender_uuid_str,
                            "msg_id": msg_id,
                        }),
                    )
                    .ok();
                    tracing::info!("deleted message {} from {}", row_id, sender_uuid_str);
                }
            }
        }
    }
}

/// Purge expired messages and emit event if any were deleted.
fn purge_expired_messages(app: &AppHandle) {
    let state = app.state::<AppState>();
    let history = state.history.lock().unwrap();
    if let Some(ref h) = *history {
        if let Ok(count) = h.purge_expired() {
            if count > 0 {
                app.emit(events::EVENT_MESSAGES_EXPIRED, count).ok();
                tracing::info!("purged {} expired messages", count);
            }
        }
    }
}

/// Poll group messages for all groups we're a member of.
async fn poll_group_messages(app: &AppHandle) {
    let state = app.state::<AppState>();

    let http = {
        let identity = state.identity.lock().unwrap();
        let id_state = match identity.as_ref() {
            Some(s) => s,
            None => return,
        };
        let h = state.http.lock().unwrap();
        match h.as_ref() {
            Some(http) => {
                let mut ed_bytes = [0u8; 32];
                ed_bytes.copy_from_slice(&id_state.identity_ed_private);
                HttpClient::with_auth(http.base_url(), id_state.device_id, &ed_bytes)
            }
            None => return,
        }
    };

    let device_id = {
        let id = state.identity.lock().unwrap();
        match id.as_ref() {
            Some(s) => s.device_id,
            None => return,
        }
    };

    // List our groups
    let groups = match http.list_groups().await {
        Ok(g) => g,
        Err(_) => return,
    };

    for group in &groups {
        let group_uuid = match uuid::Uuid::parse_str(&group.group_id) {
            Ok(u) => u,
            Err(_) => continue,
        };

        let messages = match http.receive_group_messages(group_uuid).await {
            Ok(m) => m,
            Err(_) => continue,
        };

        for gm in &messages {
            // Skip our own messages
            if gm.sender_device_id == device_id.to_string() {
                continue;
            }

            let payload_bytes = match hex::decode(&gm.payload) {
                Ok(b) => b,
                Err(_) => continue,
            };

            let group_msg: echo_crypto::group::GroupMessage = match bincode::deserialize(&payload_bytes) {
                Ok(m) => m,
                Err(_) => continue,
            };

            // Decrypt using our group session
            let plaintext = {
                let vault = state.vault.lock().unwrap();
                let mut session = match vault.load_group_session(&group.group_id) {
                    Some(s) => s,
                    None => continue,
                };

                let result = session.decrypt(&group_msg);

                // Save updated session state
                vault.save_group_session(&group.group_id, &session).ok();

                match result {
                    Ok(pt) => pt,
                    Err(e) => {
                        tracing::warn!("group decrypt failed for {}: {}", group.group_id, e);
                        continue;
                    }
                }
            };

            let text = String::from_utf8_lossy(&plaintext).to_string();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg_id = format!("grp-{}-{}", group.group_id, gm.id);

            // Store in history
            {
                let history = state.history.lock().unwrap();
                if let Some(ref h) = *history {
                    // Use sender_device_id as the "peer" within group context
                    h.insert_message(&msg_id, &group.group_id, &text, false, now).ok();
                }
            }

            let chat_msg = GroupChatMessage {
                id: msg_id,
                group_id: group.group_id.clone(),
                from_device: gm.sender_device_id.clone(),
                text,
                sent_by_me: false,
                timestamp: now,
            };

            app.emit(events::EVENT_GROUP_MESSAGE, &chat_msg).ok();
        }
    }
}
