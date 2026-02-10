use tauri::{AppHandle, Manager};

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
