use std::net::SocketAddr;

use axum::{
    routing::{get, post},
    Router,
};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api;
mod config;
mod db;
mod middleware;
mod ws;

use crate::config::ServerConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "echo_server=info,tower_http=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load config
    dotenvy::dotenv().ok();
    let config = ServerConfig::load()?;

    // Initialize database
    let db_pool = db::create_pool(&config.database_url).await?;
    db::run_migrations(&db_pool).await?;

    // Backfill short codes for existing devices
    api::keys::backfill_short_codes(&db_pool).await.ok();

    // Initialize Redis (rate limiting)
    let redis = redis::Client::open(config.redis_url.as_str())?;

    // Load transparency signing key
    let transparency_key = config::transparency::TransparencySigningKey::load_or_generate()?;
    tracing::info!(
        "Transparency public key: {}",
        hex::encode(&transparency_key.public_key)
    );

    // Build app state
    let state = api::AppState {
        db: db_pool,
        redis,
        config: config.clone(),
        transparency_key,
        ws_connections: std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
    };

    // Seed genesis invite if none exist
    {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM invite_codes")
            .fetch_one(&state.db)
            .await
            .unwrap_or((0,));
        if count == 0 {
            use sha2::{Digest, Sha256};
            let genesis_code = std::env::var("GENESIS_INVITE").unwrap_or_else(|_| {
                let mut raw = [0u8; 16];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut raw);
                hex::encode(raw)
            });
            let code_hash = Sha256::digest(genesis_code.as_bytes());
            sqlx::query(
                "INSERT INTO invite_codes (code_hash, is_genesis, expires_at) VALUES ($1, TRUE, NOW() + INTERVAL '365 days')"
            )
            .bind(&code_hash[..])
            .execute(&state.db)
            .await
            .ok();
            tracing::info!("genesis invite code created and inserted into DB");
        }
    }

    // Background: expired message queue cleanup (every hour)
    {
        let db = state.db.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                match sqlx::query("DELETE FROM message_queue WHERE expires_at < NOW()")
                    .execute(&db)
                    .await
                {
                    Ok(result) => {
                        if result.rows_affected() > 0 {
                            tracing::info!("Cleaned {} expired messages from queue", result.rows_affected());
                        }
                    }
                    Err(e) => tracing::warn!("Queue cleanup failed: {}", e),
                }
            }
        });
    }

    // Build router
    let app = Router::new()
        // Invite codes
        .route("/v1/invites/generate", post(api::invites::generate_invites))
        .route("/v1/invites/redeem", post(api::invites::redeem_invite))
        // Key management
        .route("/v1/keys/upload", post(api::keys::upload_prekeys))
        .route("/v1/keys/{device_id}", get(api::keys::fetch_prekeys))
        .route("/v1/keys/prekey-count", get(api::keys::prekey_count))
        .route("/v1/keys/upload-otps", post(api::keys::upload_additional_otps))
        // Messaging
        .route("/v1/messages/send", post(api::messages::send_message))
        .route("/v1/messages/receive", get(api::messages::receive_messages))
        .route("/v1/messages/ack", post(api::messages::ack_message))
        // Key transparency
        .route("/v1/transparency/sth", get(api::keys::get_sth))
        .route("/v1/transparency/proof/{device_id}", get(api::keys::get_transparency_proof))
        // Profiles
        .route("/v1/profile/update", post(api::profiles::update_profile))
        .route("/v1/profile/{device_id}", get(api::profiles::get_profile))
        // Short code lookup
        .route("/v1/lookup/{code}", get(api::profiles::lookup_by_code))
        // Groups
        .route("/v1/groups", post(api::groups::create_group))
        .route("/v1/groups", get(api::groups::list_groups))
        .route("/v1/groups/{group_id}/send", post(api::groups::send_group_message))
        .route("/v1/groups/{group_id}/messages", get(api::groups::receive_group_messages))
        .route("/v1/groups/{group_id}/members", post(api::groups::add_group_member))
        .route("/v1/groups/{group_id}/members", get(api::groups::get_group_members))
        .route("/v1/groups/{group_id}/leave", post(api::groups::leave_group))
        // WebSocket for real-time
        .route("/v1/ws", get(ws::websocket_handler))
        // Health
        .route("/health", get(|| async { "ok" }))
        // Middleware
        .layer(TraceLayer::new_for_http())
        .layer(middleware::rate_limit_layer())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));

    // Conditional TLS binding
    #[cfg(feature = "tls")]
    {
        if let (Some(cert_path), Some(key_path)) = (&config.tls_cert_path, &config.tls_key_path) {
            let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
                cert_path,
                key_path,
            )
            .await?;

            tracing::info!("ECHO server listening on {} (HTTPS)", addr);
            axum_server::bind_rustls(addr, tls_config)
                .serve(app.into_make_service())
                .await?;

            return Ok(());
        }
    }

    // Plain HTTP (dev mode or no TLS feature)
    if config.tls_cert_path.is_some() || config.tls_key_path.is_some() {
        tracing::warn!("TLS_CERT_PATH/TLS_KEY_PATH set but server compiled without 'tls' feature — running plain HTTP");
    }

    tracing::info!("ECHO server listening on {} (HTTP)", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
