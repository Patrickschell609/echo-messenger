use tauri::{AppHandle, Manager};
use uuid::Uuid;

use echo_client::http::HttpClient;
use echo_crypto::group::GroupSession;
use echo_crypto::types::DeviceId;

use crate::state::{AppState, GroupChatMessage, GroupInfo};

/// Helper: build an authenticated HttpClient from app state.
fn build_http(state: &AppState) -> Result<HttpClient, String> {
    let (device_id, ed_bytes) = {
        let identity = state.identity.lock().unwrap();
        let id_state = identity.as_ref().ok_or("not signed in")?;
        let mut ed = [0u8; 32];
        ed.copy_from_slice(&id_state.identity_ed_private);
        (id_state.device_id, ed)
    }; // identity lock released

    let http = state.http.lock().unwrap();
    let http_ref = http.as_ref().ok_or("no http client")?;
    Ok(HttpClient::with_auth(
        http_ref.base_url(),
        device_id,
        &ed_bytes,
    ))
}

/// Helper: get our device id.
fn our_device_id(state: &AppState) -> Result<Uuid, String> {
    let identity = state.identity.lock().unwrap();
    let id_state = identity.as_ref().ok_or("not signed in")?;
    Ok(id_state.device_id)
}

#[tauri::command]
pub async fn create_group(
    app: AppHandle,
    name: String,
    member_ids: Vec<String>,
) -> Result<GroupInfo, String> {
    let state = app.state::<AppState>();
    let http = build_http(&state)?;
    let device_id = our_device_id(&state)?;

    let member_uuids: Vec<Uuid> = member_ids
        .iter()
        .filter_map(|s| Uuid::parse_str(s).ok())
        .collect();

    let resp = http
        .create_group(&name, &member_uuids)
        .await
        .map_err(|e| e.to_string())?;

    let group_uuid = Uuid::parse_str(&resp.group_id).map_err(|e| e.to_string())?;

    // Create local GroupSession with sender key
    let mut group_id_bytes = [0u8; 16];
    group_id_bytes.copy_from_slice(group_uuid.as_bytes());

    let device_bytes = device_id.as_bytes();
    let our_dev = DeviceId(*device_bytes);

    let session = GroupSession::new(group_id_bytes, our_dev);

    // Save to vault
    {
        let vault = state.vault.lock().unwrap();
        vault
            .save_group_session(&resp.group_id, &session)
            .map_err(|e| e.to_string())?;
    }

    // Distribute our sender key to all members via pairwise sessions
    distribute_sender_key(&app, &session, &member_uuids, device_id).await;

    Ok(GroupInfo {
        group_id: resp.group_id,
        name: resp.name,
        member_count: resp.member_count,
    })
}

#[tauri::command]
pub async fn list_groups(app: AppHandle) -> Result<Vec<GroupInfo>, String> {
    let state = app.state::<AppState>();
    let http = build_http(&state)?;

    let groups = http.list_groups().await.map_err(|e| e.to_string())?;

    Ok(groups
        .into_iter()
        .map(|g| GroupInfo {
            group_id: g.group_id,
            name: g.name,
            member_count: g.member_count,
        })
        .collect())
}

#[tauri::command]
pub async fn send_group_message(
    app: AppHandle,
    group_id: String,
    message: String,
) -> Result<GroupChatMessage, String> {
    let state = app.state::<AppState>();
    let http = build_http(&state)?;
    let device_id = our_device_id(&state)?;

    let group_uuid = Uuid::parse_str(&group_id).map_err(|e| e.to_string())?;

    // Load group session, encrypt the message
    let payload = {
        let vault = state.vault.lock().unwrap();
        let mut session = vault
            .load_group_session(&group_id)
            .ok_or("no group session — rejoin group")?;

        let group_msg = session
            .encrypt(message.as_bytes())
            .map_err(|e| e.to_string())?;

        let payload = bincode::serialize(&group_msg).map_err(|e| e.to_string())?;

        // Save updated session (chain ratcheted)
        vault
            .save_group_session(&group_id, &session)
            .map_err(|e| e.to_string())?;

        payload
    };

    let _msg_id = http
        .send_group_message(group_uuid, &payload)
        .await
        .map_err(|e| e.to_string())?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let msg_id = format!("grp-{}-{}", group_id, now);

    // Store in history (reuse encrypted history with group_id as peer_id)
    {
        let history = state.history.lock().unwrap();
        if let Some(ref h) = *history {
            h.insert_message(&msg_id, &group_id, &message, true, now).ok();
        }
    }

    Ok(GroupChatMessage {
        id: msg_id,
        group_id,
        from_device: device_id.to_string(),
        text: message,
        sent_by_me: true,
        timestamp: now,
    })
}

#[tauri::command]
pub async fn load_group_history(
    app: AppHandle,
    group_id: String,
    limit: i64,
    before_timestamp: Option<u64>,
) -> Result<Vec<GroupChatMessage>, String> {
    let state = app.state::<AppState>();
    let device_id = our_device_id(&state)?;

    let history = state.history.lock().unwrap();
    let h = match history.as_ref() {
        Some(h) => h,
        None => return Ok(vec![]),
    };

    let rows = h
        .load_messages(&group_id, limit as u32, before_timestamp)
        .map_err(|e| e.to_string())?;

    let my_id = device_id.to_string();

    Ok(rows
        .into_iter()
        .map(|row| GroupChatMessage {
            id: format!("grp-hist-{}", row.id),
            group_id: group_id.clone(),
            from_device: if row.sent_by_me {
                my_id.clone()
            } else {
                row.peer_id.clone()
            },
            text: row.text,
            sent_by_me: row.sent_by_me,
            timestamp: row.timestamp,
        })
        .collect())
}

#[tauri::command]
pub async fn leave_group(app: AppHandle, group_id: String) -> Result<(), String> {
    let state = app.state::<AppState>();
    let http = build_http(&state)?;

    let group_uuid = Uuid::parse_str(&group_id).map_err(|e| e.to_string())?;

    http.leave_group(group_uuid)
        .await
        .map_err(|e| e.to_string())?;

    // Clean up local session
    {
        let vault = state.vault.lock().unwrap();
        vault.delete_group_session(&group_id).ok();
    }

    Ok(())
}

/// Distribute our sender key to group members via their pairwise 1:1 sessions.
async fn distribute_sender_key(
    app: &AppHandle,
    session: &GroupSession,
    members: &[Uuid],
    our_device_id: Uuid,
) {
    let skd = session.sender_key_distribution();
    let skd_payload = echo_client::wire::encode_skd(&skd);

    let state = app.state::<AppState>();

    for &member in members {
        if member == our_device_id {
            continue;
        }

        // Check if we have a pairwise session with this member
        let session_result: Option<(echo_crypto::ratchet::state::RatchetState, echo_client::identity::SessionMeta)> = {
            let vault = state.vault.lock().unwrap();
            vault.load_session(member).ok()
        };

        if let Some((ratchet_state, meta)) = session_result {
            let mut ratchet = echo_crypto::ratchet::TripleRatchetSession::new(ratchet_state);
            if let Ok(encrypted) = ratchet.encrypt(&skd_payload) {
                let wire_msg = if meta.needs_prekey_message {
                    echo_client::wire::WireMessage::PreKey {
                        sender_identity_key: {
                            let id = state.identity.lock().unwrap();
                            id.as_ref().map(|s| s.identity_ed_public.clone()).unwrap_or_default()
                        },
                        sender_identity_dh_key: {
                            let id = state.identity.lock().unwrap();
                            id.as_ref().map(|s| s.identity_dh_public.clone()).unwrap_or_default()
                        },
                        sender_identity_dh_signature: {
                            let id = state.identity.lock().unwrap();
                            id.as_ref().map(|s| echo_client::identity::sign_identity_dh_binding(s)).unwrap_or_default()
                        },
                        sender_ml_dsa_identity_key: {
                            let id = state.identity.lock().unwrap();
                            id.as_ref().map(|s| s.identity_mldsa_public.clone()).unwrap_or_default()
                        },
                        sender_identity_dh_ml_dsa_signature: {
                            let id = state.identity.lock().unwrap();
                            id.as_ref().map(|s| echo_client::identity::sign_identity_dh_binding_ml_dsa(s)).unwrap_or_default()
                        },
                        ephemeral_public: meta.ephemeral_public.clone(),
                        pq_ciphertext: meta.pq_ciphertext.clone(),
                        used_one_time_prekey_id: meta.used_one_time_prekey_id,
                        ratchet_header: bincode::serialize(&encrypted.header).unwrap_or_default(),
                        encrypted_header: encrypted.encrypted_header,
                        ciphertext: encrypted.ciphertext,
                    }
                } else {
                    echo_client::wire::WireMessage::Normal {
                        ratchet_header: bincode::serialize(&encrypted.header).unwrap_or_default(),
                        encrypted_header: encrypted.encrypted_header,
                        ciphertext: encrypted.ciphertext,
                    }
                };

                let wire_bytes = bincode::serialize(&wire_msg).unwrap_or_default();

                // Seal with sender cert
                let sender_cert: Option<echo_crypto::sealed_sender::SenderCertificate> = {
                    let vault = state.vault.lock().unwrap();
                    vault.load_sender_cert()
                };

                if let Some(cert) = sender_cert {
                    let recipient_dh = meta.recipient_dh_key;

                    if let Ok(sealed) =
                        echo_crypto::sealed_sender::seal_message(&recipient_dh, &cert, &wire_bytes)
                    {
                        let envelope = bincode::serialize(&sealed).unwrap_or_default();

                        // Lock identity first, then http (same order as everywhere else to avoid deadlock)
                        let http = {
                            let id = state.identity.lock().unwrap();
                            let id_state = match id.as_ref() {
                                Some(s) => s,
                                None => continue,
                            };
                            let mut ed_bytes = [0u8; 32];
                            ed_bytes.copy_from_slice(&id_state.identity_ed_private);
                            let device_id = id_state.device_id;
                            let h = state.http.lock().unwrap();
                            h.as_ref().map(|c| {
                                HttpClient::with_auth(c.base_url(), device_id, &ed_bytes)
                            })
                        };

                        if let Some(http) = http {
                            http.send_message(member, &envelope).await.ok();
                        }
                    }
                }

                // Update ratchet state
                {
                    let vault = state.vault.lock().unwrap();
                    vault.update_session(member, &ratchet.export_state()).ok();
                }
            }
        }
    }
}
