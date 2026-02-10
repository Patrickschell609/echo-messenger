use tauri::{AppHandle, Manager};

use echo_client::http::{HttpClient, ProfileResponse};

use crate::state::AppState;

/// Update your display name on the server.
#[tauri::command]
pub async fn update_profile(
    app: AppHandle,
    display_name: String,
) -> Result<ProfileResponse, String> {
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

    let profile = http
        .update_profile(Some(&display_name), None)
        .await
        .map_err(|e| e.to_string())?;

    // Cache in vault
    {
        let vault = state.vault.lock().unwrap();
        let mut profiles: std::collections::HashMap<String, ProfileResponse> = vault
            .read_file("profiles.enc")
            .unwrap_or_default();
        profiles.insert(profile.device_id.clone(), profile.clone());
        vault.write_file("profiles.enc", &profiles).ok();
    }

    Ok(profile)
}

/// Fetch a peer's profile from server (with local cache).
#[tauri::command]
pub async fn fetch_profile(
    app: AppHandle,
    device_id: String,
) -> Result<ProfileResponse, String> {
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

    let target: uuid::Uuid = device_id.parse().map_err(|e| format!("Invalid UUID: {}", e))?;

    match http.fetch_profile(target).await {
        Ok(profile) => {
            // Cache in vault
            {
                let vault = state.vault.lock().unwrap();
                let mut profiles: std::collections::HashMap<String, ProfileResponse> = vault
                    .read_file("profiles.enc")
                    .unwrap_or_default();
                profiles.insert(profile.device_id.clone(), profile.clone());
                vault.write_file("profiles.enc", &profiles).ok();
            }
            Ok(profile)
        }
        Err(_) => {
            // Fall back to cached profile
            let vault = state.vault.lock().unwrap();
            let profiles: std::collections::HashMap<String, ProfileResponse> = vault
                .read_file("profiles.enc")
                .unwrap_or_default();
            profiles
                .get(&device_id)
                .cloned()
                .ok_or_else(|| "Profile not found".to_string())
        }
    }
}
