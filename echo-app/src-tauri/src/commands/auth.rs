use tauri::{AppHandle, Emitter, Manager};
use zeroize::Zeroize;

use echo_client::history::EncryptedHistory;
use echo_client::http::HttpClient;
use echo_client::identity::KeyMaterial;
use echo_client::outbox::OutboxQueue;
use echo_client::storage::EncryptedVault;

use crate::events;
use crate::state::AppState;

#[derive(serde::Serialize)]
pub struct SignOnResult {
    pub device_id: String,
    pub account_id: String,
    pub short_code: Option<String>,
}

/// Create a new account on the server via invite code, generate keys, save to vault.
#[tauri::command]
pub async fn create_account(
    app: AppHandle,
    server_url: String,
    passphrase: String,
    invite_code: String,
) -> Result<SignOnResult, String> {
    let state = app.state::<AppState>();

    // Set server URL
    *state.server_url.lock().unwrap() = server_url.clone();
    let http = HttpClient::new(&server_url);

    // Redeem invite code — returns account_id + one-time auth_nonce
    let (account_id, auth_nonce) = http.redeem_invite(&invite_code).await.map_err(|e| e.to_string())?;

    // Generate keys
    let keys = KeyMaterial::generate();

    // Upload prekeys with auth nonce + signature — returns device_id + signed sender cert + short code
    let (device_id, sender_cert_bytes, short_code) = http.upload_prekeys(account_id, &keys, Some(&auth_nonce)).await.map_err(|e| e.to_string())?;
    let short_code_for_result = short_code.clone();

    // Build identity state directly (no plaintext IdentityStore)
    let identity_state = echo_client::identity::IdentityState {
        account_id,
        device_id,
        identity_ed_private: keys.identity_ed.private_key_bytes().0.to_vec(),
        identity_ed_public: keys.identity_ed.public_key().0.to_vec(),
        identity_dh_private: keys.identity_dh.private_key_bytes().0.to_vec(),
        identity_dh_public: keys.identity_dh.public_key().0.to_vec(),
        signed_prekey_private: keys.signed_prekey.private_key_bytes().0.to_vec(),
        signed_prekey_public: keys.signed_prekey.public_key().0.to_vec(),
        signed_prekey_id: keys.signed_prekey_id,
        pq_pk: keys.pq_pk.0.clone(),
        pq_sk: keys.pq_sk.0.clone(),
        pq_prekey_id: keys.pq_prekey_id,
        one_time_prekeys: keys
            .one_time_prekeys
            .iter()
            .map(|(id, kp)| (*id, kp.private_key_bytes().0.to_vec()))
            .collect(),
        last_rotation_time: None,
        prev_signed_prekey_private: None,
        prev_signed_prekey_id: None,
        prev_pq_sk: None,
        prev_pq_prekey_id: None,
        prev_key_expiry: None,
        short_code,
    };

    // Initialize encrypted vault
    let vault_path = crate::state::vault_path().map_err(|e| e.to_string())?;
    let mut vault = EncryptedVault::new(&vault_path);
    vault.create(&passphrase).map_err(|e| e.to_string())?;

    // Save identity to vault
    vault.write_file("identity.enc", &identity_state).map_err(|e| e.to_string())?;

    // Save contacts (empty)
    let contacts: Vec<crate::state::Contact> = Vec::new();
    vault.write_file("contacts.enc", &contacts).map_err(|e| e.to_string())?;

    // Save server-signed sender certificate if provided, counter-signing with our Ed25519 key (C1)
    if let Some(cert_bytes) = sender_cert_bytes {
        if let Ok(mut cert) = bincode::deserialize::<echo_crypto::sealed_sender::SenderCertificate>(&cert_bytes) {
            let mut ed_priv = [0u8; 32];
            ed_priv.copy_from_slice(&identity_state.identity_ed_private);
            echo_crypto::sealed_sender::countersign_sender_cert(&mut cert, &ed_priv);
            ed_priv.zeroize();
            vault.save_sender_cert(&cert).map_err(|e| e.to_string())?;
        }
    }

    // Init encrypted history
    let history_key = vault.derive_sub_key("history").map_err(|e| e.to_string())?;
    let db_path = vault.vault_dir().join("history.db");
    let history = EncryptedHistory::open(&db_path, history_key).map_err(|e| e.to_string())?;

    // Init encrypted outbox
    let outbox_key = vault.derive_sub_key("outbox").map_err(|e| e.to_string())?;
    let outbox_path = vault.vault_dir().join("outbox.db");
    let outbox = OutboxQueue::open_encrypted(&outbox_path, outbox_key).map_err(|e| e.to_string())?;

    // Build authenticated HTTP client
    let mut ed_bytes = [0u8; 32];
    ed_bytes.copy_from_slice(&identity_state.identity_ed_private);
    let auth_http = HttpClient::with_auth(&server_url, device_id, &ed_bytes);

    // Update app state
    *state.http.lock().unwrap() = Some(auth_http);
    *state.vault.lock().unwrap() = vault;
    *state.identity.lock().unwrap() = Some(identity_state);
    *state.signed_in.lock().unwrap() = true;
    *state.history.lock().unwrap() = Some(history);
    *state.outbox.lock().unwrap() = Some(outbox);

    let result = SignOnResult {
        device_id: device_id.to_string(),
        account_id: account_id.to_string(),
        short_code: short_code_for_result,
    };

    app.emit(events::EVENT_SIGNED_IN, &result).ok();

    Ok(result)
}

/// Sign on with existing account (unlock vault, load identity).
#[tauri::command]
pub async fn sign_on(
    app: AppHandle,
    server_url: String,
    passphrase: String,
) -> Result<SignOnResult, String> {
    let state = app.state::<AppState>();

    *state.server_url.lock().unwrap() = server_url.clone();

    // Unlock vault
    let vault_path = crate::state::vault_path().map_err(|e| e.to_string())?;
    let mut vault = EncryptedVault::new(&vault_path);
    vault.unlock(&passphrase).map_err(|_| "Wrong passphrase or no account found".to_string())?;

    // Migrate legacy plaintext files if they exist
    migrate_legacy_store(&vault);

    // Load identity from vault
    let identity_state: echo_client::identity::IdentityState = vault
        .read_file("identity.enc")
        .map_err(|e| format!("Failed to load identity: {}", e))?;

    let device_id = identity_state.device_id;
    let account_id = identity_state.account_id;

    // Init encrypted history
    let history_key = vault.derive_sub_key("history").map_err(|e| e.to_string())?;
    let db_path = vault.vault_dir().join("history.db");
    let history = EncryptedHistory::open(&db_path, history_key).map_err(|e| e.to_string())?;

    // Init encrypted outbox
    let outbox_key = vault.derive_sub_key("outbox").map_err(|e| e.to_string())?;
    let outbox_path = vault.vault_dir().join("outbox.db");
    let outbox = OutboxQueue::open_encrypted(&outbox_path, outbox_key).map_err(|e| e.to_string())?;

    // Build authenticated HTTP client
    let mut ed_bytes = [0u8; 32];
    ed_bytes.copy_from_slice(&identity_state.identity_ed_private);
    let auth_http = HttpClient::with_auth(&server_url, device_id, &ed_bytes);

    let short_code = identity_state.short_code.clone();

    // Update state
    *state.http.lock().unwrap() = Some(auth_http);
    *state.vault.lock().unwrap() = vault;
    *state.identity.lock().unwrap() = Some(identity_state);
    *state.signed_in.lock().unwrap() = true;
    *state.history.lock().unwrap() = Some(history);
    *state.outbox.lock().unwrap() = Some(outbox);

    let result = SignOnResult {
        device_id: device_id.to_string(),
        account_id: account_id.to_string(),
        short_code,
    };

    app.emit(events::EVENT_SIGNED_IN, &result).ok();

    Ok(result)
}

/// Sign off — zeroize keys, lock vault, close history.
#[tauri::command]
pub async fn sign_off(app: AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();

    // Clean up unencrypted media files
    let media_dir = crate::commands::messaging::media_dir();
    if media_dir.exists() {
        std::fs::remove_dir_all(&media_dir).ok();
    }

    *state.signed_in.lock().unwrap() = false;
    *state.identity.lock().unwrap() = None;
    *state.http.lock().unwrap() = None;
    *state.history.lock().unwrap() = None; // Drop closes DB + zeroizes key
    *state.outbox.lock().unwrap() = None;  // Drop closes outbox DB
    *state.ws_tx.lock().unwrap() = None;
    state.vault.lock().unwrap().zeroize();

    app.emit(events::EVENT_SIGNED_OUT, ()).ok();

    Ok(())
}

/// Check if a vault already exists (for showing Sign On vs Create Account).
#[tauri::command]
pub fn vault_exists() -> bool {
    crate::state::vault_path()
        .map(|p| p.join("salt.bin").exists())
        .unwrap_or(false)
}

/// Generate invite codes (authenticated, requires signed-in state).
#[tauri::command]
pub async fn generate_invites(
    app: AppHandle,
    count: u32,
) -> Result<Vec<String>, String> {
    let state = app.state::<AppState>();

    let signed_in = *state.signed_in.lock().unwrap();
    if !signed_in {
        return Err("Not signed in".to_string());
    }

    let identity_state = {
        let id = state.identity.lock().unwrap();
        id.as_ref().cloned().ok_or("No identity loaded".to_string())?
    };

    let http = {
        let h = state.http.lock().unwrap();
        match h.as_ref() {
            Some(http) => {
                let mut ed_bytes = [0u8; 32];
                ed_bytes.copy_from_slice(&identity_state.identity_ed_private);
                HttpClient::with_auth(http.base_url(), identity_state.device_id, &ed_bytes)
            }
            None => return Err("No HTTP client".to_string()),
        }
    };

    let codes = http.generate_invites(count).await.map_err(|e| e.to_string())?;
    Ok(codes)
}

/// Migrate legacy plaintext ~/.echo/ files into the encrypted vault, then delete originals.
fn migrate_legacy_store(vault: &EncryptedVault) {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return,
    };
    let legacy_dir = home.join(".echo");
    if !legacy_dir.exists() {
        return;
    }

    tracing::info!("found legacy ~/.echo/ directory, migrating to vault...");

    // Walk subdirectories looking for identity.json and session files
    if let Ok(entries) = std::fs::read_dir(&legacy_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            // Migrate identity.json
            let identity_path = path.join("identity.json");
            if identity_path.exists() {
                if let Ok(json) = std::fs::read_to_string(&identity_path) {
                    if let Ok(state) = serde_json::from_str::<echo_client::identity::IdentityState>(&json) {
                        if !vault.file_exists("identity.enc") {
                            vault.write_file("identity.enc", &state).ok();
                        }
                    }
                }
            }

            // Migrate session files
            let sessions_dir = path.join("sessions");
            if sessions_dir.exists() {
                if let Ok(session_entries) = std::fs::read_dir(&sessions_dir) {
                    for se in session_entries.flatten() {
                        let name = se.file_name().to_string_lossy().to_string();
                        if name.ends_with(".ratchet.json") {
                            let uuid_str = name.trim_end_matches(".ratchet.json");
                            let vault_path = format!("sessions/{}.ratchet.enc", uuid_str);
                            if !vault.file_exists(&vault_path) {
                                if let Ok(json) = std::fs::read_to_string(se.path()) {
                                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json) {
                                        vault.write_file(&vault_path, &val).ok();
                                    }
                                }
                            }
                        } else if name.ends_with(".meta.json") {
                            let uuid_str = name.trim_end_matches(".meta.json");
                            let vault_path = format!("sessions/{}.meta.enc", uuid_str);
                            if !vault.file_exists(&vault_path) {
                                if let Ok(json) = std::fs::read_to_string(se.path()) {
                                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json) {
                                        vault.write_file(&vault_path, &val).ok();
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Migrate STH
            let sth_path = path.join("last_sth.json");
            if sth_path.exists() && !vault.file_exists("last_sth.enc") {
                if let Ok(json) = std::fs::read_to_string(&sth_path) {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json) {
                        vault.write_file("last_sth.enc", &val).ok();
                    }
                }
            }

            // Migrate server transparency key
            let tk_path = path.join("server_transparency_key.hex");
            if tk_path.exists() && !vault.file_exists("server_transparency_key.enc") {
                if let Ok(hex_str) = std::fs::read_to_string(&tk_path) {
                    vault.write_file("server_transparency_key.enc", &hex_str.trim().to_string()).ok();
                }
            }
        }
    }

    // Delete legacy directory
    if std::fs::remove_dir_all(&legacy_dir).is_ok() {
        tracing::info!("deleted legacy ~/.echo/ directory after migration");
    }
}
