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
            server_pubkey = Some(sth_resp.server_public_key);
        }
    }

    // Verify transparency (sync)
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
        ) {
            Ok(()) => {
                let vault = state.vault.lock().unwrap();
                vault.save_last_sth(&tp.sth).ok();
                verified = true;
            }
            Err(e) => {
                return Err(format!("Transparency verification FAILED: {}", e));
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

    // Save session to vault
    {
        let vault = state.vault.lock().unwrap();
        vault
            .save_session(recipient_device, &ratchet_state, &meta)
            .map_err(|e| e.to_string())?;
    }

    let result = SessionResult {
        device_id: device_id.clone(),
        verified,
    };

    app.emit(events::EVENT_SESSION_ESTABLISHED, &device_id).ok();

    Ok(result)
}
