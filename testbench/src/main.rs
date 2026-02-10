mod routes;
mod runner;
mod state;

use axum::routing::{get, post};
use axum::Router;
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};

use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Resolve the echo CLI binary
    let echo_bin = std::env::var("ECHO_BIN").unwrap_or_else(|_| find_echo_bin());
    let server_url =
        std::env::var("ECHO_SERVER").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let port: u16 = std::env::var("TESTBENCH_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(9090);

    tracing::info!("Echo binary: {echo_bin}");
    tracing::info!("Echo server: {server_url}");

    let state = AppState::new(echo_bin, server_url);

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/", get(routes::index))
        .route("/api/register", post(routes::register))
        .route("/api/whoami", post(routes::whoami))
        .route("/api/session", post(routes::session))
        .route("/api/send", post(routes::send_msg))
        .route("/api/recv", post(routes::recv))
        .route("/api/monitor", post(routes::monitor))
        .route("/api/state", post(routes::read_state))
        .route("/api/reset", post(routes::reset))
        .route("/api/logs", get(routes::logs))
        .layer(cors)
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    tracing::info!("Testbench at http://{addr}");
    println!("\n  ECHO Testbench → http://127.0.0.1:{port}\n");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn find_echo_bin() -> String {
    // Try common locations relative to workspace root
    let candidates = [
        "target/debug/echo",
        "target/release/echo",
        "../target/debug/echo",
        "../target/release/echo",
    ];
    for c in &candidates {
        let path = std::path::Path::new(c);
        if path.exists() {
            return path.canonicalize()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| c.to_string());
        }
    }
    // Fallback: hope it's on PATH
    "echo".to_string()
}
