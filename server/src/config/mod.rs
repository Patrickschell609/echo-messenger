pub mod transparency;

use serde::{Deserialize, Serialize};

/// Server configuration loaded from environment variables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub port: u16,
    pub database_url: String,
    pub redis_url: String,
    pub sms_api_key: String,
    /// Path to TLS certificate PEM file (enables HTTPS when set)
    pub tls_cert_path: Option<String>,
    /// Path to TLS private key PEM file
    pub tls_key_path: Option<String>,
}

impl ServerConfig {
    /// Load configuration from environment variables.
    ///
    /// Expected env vars:
    /// - `PORT` (defaults to 8080)
    /// - `DATABASE_URL`
    /// - `REDIS_URL`
    /// - `SMS_API_KEY`
    pub fn load() -> anyhow::Result<Self> {
        let port = std::env::var("PORT")
            .unwrap_or_else(|_| "8080".into())
            .parse::<u16>()?;

        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| anyhow::anyhow!("DATABASE_URL must be set"))?;

        let redis_url = std::env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".into());

        let sms_api_key = std::env::var("SMS_API_KEY").unwrap_or_default();

        let tls_cert_path = std::env::var("TLS_CERT_PATH").ok();
        let tls_key_path = std::env::var("TLS_KEY_PATH").ok();

        Ok(Self {
            port,
            database_url,
            redis_url,
            sms_api_key,
            tls_cert_path,
            tls_key_path,
        })
    }
}
