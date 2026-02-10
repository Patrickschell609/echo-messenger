use serde::Serialize;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    pub echo_bin: String,
    pub server_url: String,
    pub log_tx: broadcast::Sender<LogEntry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub identity: String,
    pub command: String,
    pub level: String,
    pub message: String,
}

impl AppState {
    pub fn new(echo_bin: String, server_url: String) -> Self {
        let (log_tx, _) = broadcast::channel(256);
        Self {
            inner: Arc::new(Inner {
                echo_bin,
                server_url,
                log_tx,
            }),
        }
    }

    pub fn echo_bin(&self) -> &str {
        &self.inner.echo_bin
    }

    pub fn server_url(&self) -> &str {
        &self.inner.server_url
    }

    pub fn subscribe(&self) -> broadcast::Receiver<LogEntry> {
        self.inner.log_tx.subscribe()
    }

    pub fn emit(&self, identity: &str, command: &str, level: &str, message: &str) {
        let secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let h = (secs / 3600) % 24;
        let m = (secs / 60) % 60;
        let s = secs % 60;
        let now = format!("{h:02}:{m:02}:{s:02}");
        let entry = LogEntry {
            timestamp: now,
            identity: identity.to_string(),
            command: command.to_string(),
            level: level.to_string(),
            message: message.to_string(),
        };
        // Ignore send errors (no subscribers yet)
        let _ = self.inner.log_tx.send(entry);
    }
}
