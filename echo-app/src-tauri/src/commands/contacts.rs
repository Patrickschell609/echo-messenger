use tauri::{AppHandle, Manager};

use echo_client::http::HttpClient;

use crate::state::{AppState, Contact};

/// Add a buddy by device UUID.
#[tauri::command]
pub async fn add_buddy(
    app: AppHandle,
    device_id: String,
    display_name: String,
) -> Result<Contact, String> {
    let state = app.state::<AppState>();

    // Validate UUID
    let _: uuid::Uuid = device_id.parse().map_err(|e| format!("Invalid UUID: {}", e))?;

    let vault = state.vault.lock().unwrap();
    if !vault.is_unlocked() {
        return Err("Vault locked".to_string());
    }

    // Load existing contacts
    let mut contacts: Vec<Contact> = vault
        .read_file("contacts.enc")
        .unwrap_or_default();

    // Check not duplicate
    if contacts.iter().any(|c| c.device_id.to_string() == device_id) {
        return Err("Buddy already exists".to_string());
    }

    // Check if session exists via vault
    let uuid: uuid::Uuid = device_id.parse().unwrap();
    let has_session = vault.session_exists(uuid);

    let contact = Contact {
        device_id: device_id.parse().unwrap(),
        display_name: if display_name.is_empty() {
            format!("{}...", &device_id[..8])
        } else {
            display_name
        },
        has_session,
    };

    contacts.push(contact.clone());
    vault.write_file("contacts.enc", &contacts).map_err(|e| e.to_string())?;

    Ok(contact)
}

/// Remove a buddy.
#[tauri::command]
pub async fn remove_buddy(app: AppHandle, device_id: String) -> Result<(), String> {
    let state = app.state::<AppState>();
    let vault = state.vault.lock().unwrap();
    if !vault.is_unlocked() {
        return Err("Vault locked".to_string());
    }

    let mut contacts: Vec<Contact> = vault
        .read_file("contacts.enc")
        .unwrap_or_default();

    contacts.retain(|c| c.device_id.to_string() != device_id);
    vault.write_file("contacts.enc", &contacts).map_err(|e| e.to_string())?;

    Ok(())
}

/// List all buddies.
#[tauri::command]
pub fn list_buddies(app: AppHandle) -> Result<Vec<Contact>, String> {
    let state = app.state::<AppState>();
    let vault = state.vault.lock().unwrap();
    if !vault.is_unlocked() {
        return Err("Vault locked".to_string());
    }

    let mut contacts: Vec<Contact> = vault
        .read_file("contacts.enc")
        .unwrap_or_default();

    // Update session status from vault
    for contact in &mut contacts {
        contact.has_session = vault.session_exists(contact.device_id);
    }

    Ok(contacts)
}

/// Lookup result returned to the frontend.
#[derive(serde::Serialize)]
pub struct LookupResult {
    pub device_id: String,
    pub display_name: Option<String>,
    pub short_code: String,
}

/// Lookup a device by short code (e.g. "A7X2-KM9P").
#[tauri::command]
pub async fn lookup_code(app: AppHandle, code: String) -> Result<LookupResult, String> {
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
                HttpClient::with_auth(http.base_url(), identity_state.device_id, &ed_bytes, &identity_state.identity_mldsa_private)
            }
            None => return Err("No HTTP client".to_string()),
        }
    };

    let resp = http.lookup_by_code(&code).await.map_err(|e| e.to_string())?;

    Ok(LookupResult {
        device_id: resp.device_id,
        display_name: resp.display_name,
        short_code: resp.short_code,
    })
}

/// Get the current user's short code.
#[tauri::command]
pub fn get_short_code(app: AppHandle) -> Result<Option<String>, String> {
    let state = app.state::<AppState>();
    let id = state.identity.lock().unwrap();
    match id.as_ref() {
        Some(s) => Ok(s.short_code.clone()),
        None => Err("Not signed in".to_string()),
    }
}
