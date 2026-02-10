use std::sync::Mutex;

use echo_client::history::EncryptedHistory;
use echo_client::http::HttpClient;
use echo_client::identity::IdentityState;
use echo_client::outbox::OutboxQueue;
use echo_client::storage::EncryptedVault;
use echo_client::ws::WsOutbound;
use uuid::Uuid;

/// Shared application state, managed by Tauri.
pub struct AppState {
    pub http: Mutex<Option<HttpClient>>,
    pub vault: Mutex<EncryptedVault>,
    pub identity: Mutex<Option<IdentityState>>,
    pub server_url: Mutex<String>,
    pub signed_in: Mutex<bool>,
    pub history: Mutex<Option<EncryptedHistory>>,
    pub outbox: Mutex<Option<OutboxQueue>>,
    pub ws_tx: Mutex<Option<tokio::sync::mpsc::Sender<WsOutbound>>>,
}

impl AppState {
    pub fn new() -> Self {
        let vault_path = EncryptedVault::default_path()
            .unwrap_or_else(|_| std::path::PathBuf::from("/tmp/echo-vault"));
        Self {
            http: Mutex::new(None),
            vault: Mutex::new(EncryptedVault::new(&vault_path)),
            identity: Mutex::new(None),
            server_url: Mutex::new("http://localhost:8080".to_string()),
            signed_in: Mutex::new(false),
            history: Mutex::new(None),
            outbox: Mutex::new(None),
            ws_tx: Mutex::new(None),
        }
    }
}

/// Contact entry for the buddy list.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Contact {
    pub device_id: Uuid,
    pub display_name: String,
    pub has_session: bool,
}

/// Group info for display.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct GroupInfo {
    pub group_id: String,
    pub name: String,
    pub member_count: i64,
}

/// Group chat message for display.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct GroupChatMessage {
    pub id: String,
    pub group_id: String,
    pub from_device: String,
    pub text: String,
    pub sent_by_me: bool,
    pub timestamp: u64,
}

/// Chat message for display.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ChatMessage {
    pub id: String,
    pub from_device: String,
    pub text: String,
    pub sent_by_me: bool,
    pub timestamp: u64,
    pub status: u8, // 0=sent, 1=delivered, 2=read
    #[serde(default)]
    pub edited: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_mime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_filename: Option<String>,
}
