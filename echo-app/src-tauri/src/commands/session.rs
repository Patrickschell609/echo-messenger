use tauri::{AppHandle, Emitter, Manager};

use echo_client::http::HttpClient;
use echo_client::identity;
use echo_client::transparency;

use crate::events;
use crate::state::AppState;

#[derive(serde::Serialize)]
pub struct SessionResult {
    pub device_id: String,
    pub verified: bool,
}

/// Establish an encrypted session with a remote device via X4DH.
#[tauri::command]
pub async fn establish_session(
    app: AppHandle,
    device_id: String,
) -> Result<SessionResult, String> {
    let state = app.state::<AppState>();

    let identity_state = {
        let id = state.identity.lock().unwrap();
        id.clone().ok_or("Not signed in")?
    };

    // If poller already established a session (from a received PreKey message),
    // don't overwrite it with a new independent session — that breaks bidirectional messaging.
    let recipient_uuid: uuid::Uuid = device_id.parse().map_err(|e| format!("Invalid UUID: {}", e))?;
    tracing::info!("⚡ SESSION establish_session called for {} (our_id={})", recipient_uuid, identity_state.device_id);
    {
        let vault = state.vault.lock().unwrap();
        if vault.session_exists(recipient_uuid) {
            tracing::info!("⚡ SESSION already exists for {} — skipping X4DH", recipient_uuid);
            app.emit(events::EVENT_SESSION_ESTABLISHED, &device_id).ok();
            return Ok(SessionResult {
                device_id,
                verified: true,
            });
        }
    }
    tracing::info!("⚡ SESSION no existing session for {} — starting X4DH initiate", recipient_uuid);

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

    let recipient_device = recipient_uuid;

    // Read cached STH and server pubkey from vault (lock + release before await)
    let (last_sth, server_pubkey) = {
        let vault = state.vault.lock().unwrap();
        let sth: Option<echo_crypto::transparency::SignedTreeHead> = vault.load_last_sth();
        let spk: Option<String> = vault.load_server_transparency_key();
        (sth, spk)
    };
    let last_tree_size = last_sth.as_ref().map(|s| s.tree_size);

    // Async: fetch prekeys
    let bundle = http
        .fetch_prekeys(identity_state.device_id, recipient_device, last_tree_size)
        .await
        .map_err(|e| e.to_string())?;

    // Async: fetch STH if needed
    let mut server_pubkey = server_pubkey;
    if server_pubkey.is_none() {
        if let Ok(sth_resp) = http.fetch_sth().await {
            let vault = state.vault.lock().unwrap();
            vault.save_server_transparency_key(&sth_resp.server_public_key).ok();
            vault.save_server_ml_dsa_key(&sth_resp.server_ml_dsa_public).ok();
            server_pubkey = Some(sth_resp.server_public_key);
        }
    }
    let server_ml_dsa = {
        let vault = state.vault.lock().unwrap();
        hex::decode(vault.load_server_ml_dsa_key().unwrap_or_default()).unwrap_or_default()
    };

    // Verify transparency (sync) — auto-recover on stale cache
    let mut verified = false;
    if let Some(ref tp) = bundle.transparency {
        let ik_bytes = hex::decode(&bundle.identity_key).map_err(|e| e.to_string())?;
        let idk_bytes = hex::decode(&bundle.identity_dh_key).map_err(|e| e.to_string())?;

        match transparency::verify_transparency(
            tp,
            &ik_bytes,
            &idk_bytes,
            last_sth.as_ref(),
            server_pubkey.as_deref(),
            &server_ml_dsa,
        ) {
            Ok(()) => {
                let vault = state.vault.lock().unwrap();
                vault.save_last_sth(&tp.sth).ok();
                verified = true;
            }
            Err(e) => {
                let err_str = e.to_string();
                // Consistency failure means the tree grew (new devices registered).
                // Clear stale cache and retry with TOFU instead of blocking the session.
                if err_str.contains("consistency") && last_sth.is_some() {
                    tracing::warn!("Transparency consistency stale, resetting to TOFU: {}", err_str);
                    let vault = state.vault.lock().unwrap();
                    vault.delete_file("last_sth.enc").ok();
                    // Retry without cached STH (TOFU)
                    match transparency::verify_transparency(
                        tp,
                        &ik_bytes,
                        &idk_bytes,
                        None,
                        server_pubkey.as_deref(),
                        &server_ml_dsa,
                    ) {
                        Ok(()) => {
                            vault.save_last_sth(&tp.sth).ok();
                            verified = true;
                        }
                        Err(e2) => {
                            return Err(format!("Transparency verification FAILED: {}", e2));
                        }
                    }
                } else {
                    return Err(format!("Transparency verification FAILED: {}", e));
                }
            }
        }
    }

    // X4DH (sync)
    let keys = identity_state.reconstruct_keys();
    let prekey_bundle = bundle.to_prekey_bundle().map_err(|e| e.to_string())?;

    let init_result = echo_crypto::ratchet::x4dh::X4DH::initiate(
        &keys.identity_ed,
        &keys.identity_dh,
        &prekey_bundle,
    )
    .map_err(|e| e.to_string())?;

    let ratchet_state = identity::build_initiator_state(&keys, &prekey_bundle, &init_result);

    let meta = echo_client::identity::SessionMeta {
        recipient_device_id: recipient_device,
        recipient_identity_key: ratchet_state.remote_identity.0.to_vec(),
        recipient_dh_key: prekey_bundle.identity_dh_key.clone(),
        ephemeral_public: init_result.ephemeral_public.0.to_vec(),
        pq_ciphertext: init_result.pq_ciphertext.0.clone(),
        used_one_time_prekey_id: init_result.used_one_time_prekey_id,
        needs_prekey_message: true,
    };

    tracing::info!(
        "⚡ SESSION X4DH complete for {} — sending PreKey message immediately",
        recipient_device,
    );

    // Encrypt a SessionInit control message as the PreKey payload
    let init_payload = echo_client::wire::encode_ctrl(&echo_client::wire::ControlMessage::SessionInit);
    let mut session = echo_crypto::ratchet::TripleRatchetSession::new(ratchet_state);
    let encrypted = session.encrypt(&init_payload).map_err(|e| e.to_string())?;

    let header_bytes = bincode::serialize(&encrypted.header).map_err(|e| e.to_string())?;
    let wire_msg = echo_client::wire::WireMessage::PreKey {
        sender_identity_key: identity_state.identity_ed_public.clone(),
        sender_identity_dh_key: identity_state.identity_dh_public.clone(),
        sender_identity_dh_signature: identity::sign_identity_dh_binding(&identity_state),
        sender_ml_dsa_identity_key: identity_state.identity_mldsa_public.clone(),
        sender_identity_dh_ml_dsa_signature: identity::sign_identity_dh_binding_ml_dsa(&identity_state),
        ephemeral_public: meta.ephemeral_public.clone(),
        pq_ciphertext: meta.pq_ciphertext.clone(),
        used_one_time_prekey_id: meta.used_one_time_prekey_id,
        ratchet_header: header_bytes,
        encrypted_header: encrypted.encrypted_header,
        ciphertext: encrypted.ciphertext,
    };

    let wire_payload = bincode::serialize(&wire_msg).map_err(|e| e.to_string())?;

    // Seal with sender cert.
    // M4 (Apr 21 audit): require the server-signed cert — a self-built fallback has a
    // zero server_signature and is rejected by the recipient's unseal_message(), so the
    // PreKey message would be silently dropped. Hard-fail rather than ship a dead cert.
    let cert: echo_crypto::sealed_sender::SenderCertificate = {
        let vault = state.vault.lock().unwrap();
        vault.load_sender_cert().ok_or_else(|| {
            "missing server-signed sender certificate — re-register to obtain one".to_string()
        })?
    };
    let envelope = echo_crypto::sealed_sender::seal_message(
        &meta.recipient_dh_key,
        &cert,
        &wire_payload,
    )
    .map_err(|e| e.to_string())?;

    let envelope_bytes = bincode::serialize(&envelope).map_err(|e| e.to_string())?;

    // Persist ratchet state BEFORE network send (AV-06: prevents nonce reuse on retry)
    let updated_ratchet = session.export_state().clone();
    let mut updated_meta = meta;
    updated_meta.needs_prekey_message = false; // PreKey sent
    {
        let vault = state.vault.lock().unwrap();
        vault
            .save_session(recipient_device, &updated_ratchet, &updated_meta)
            .map_err(|e| e.to_string())?;
    }

    // Send the PreKey message to the server
    match http.send_message(recipient_device, &envelope_bytes).await {
        Ok(()) => {
            tracing::info!("⚡ SESSION PreKey message delivered to server for {}", recipient_device);
        }
        Err(e) => {
            tracing::warn!("⚡ SESSION PreKey send failed for {}: {} — queuing to outbox", recipient_device, e);
            let outbox = state.outbox.lock().unwrap();
            if let Some(ref ob) = *outbox {
                let msg_id = format!("{}-prekey-init", recipient_device);
                ob.queue_message(&device_id, &msg_id, &envelope_bytes).ok();
            }
        }
    }

    let result = SessionResult {
        device_id: device_id.clone(),
        verified,
    };

    app.emit(events::EVENT_SESSION_ESTABLISHED, &device_id).ok();

    Ok(result)
}
