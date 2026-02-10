use axum::{
    extract::State,
    http::StatusCode,
    response::{
        sse::{Event, Sse},
        Html,
    },
    Json,
};
use futures_util::stream::Stream;
use serde::Deserialize;
use std::convert::Infallible;
use std::path::PathBuf;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::runner::run_echo;
use crate::state::AppState;

static DASHBOARD_HTML: &str = include_str!("dashboard.html");

// ── Serve dashboard ──────────────────────────────────────────

pub async fn index() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

// ── Request types ────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterReq {
    identity: String,
    phone: String,
}

#[derive(Deserialize)]
pub struct IdentityReq {
    identity: String,
}

#[derive(Deserialize)]
pub struct SessionReq {
    identity: String,
    device: String,
}

#[derive(Deserialize)]
pub struct SendReq {
    identity: String,
    to: String,
    message: String,
}

// ── Handlers ─────────────────────────────────────────────────

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let output = run_echo(&state, &req.identity, &["register", "--phone", &req.phone], "register")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(parse_output(&output)))
}

pub async fn whoami(
    State(state): State<AppState>,
    Json(req): Json<IdentityReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let output = run_echo(&state, &req.identity, &["whoami"], "whoami")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(parse_output(&output)))
}

pub async fn session(
    State(state): State<AppState>,
    Json(req): Json<SessionReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let output = run_echo(&state, &req.identity, &["session", "--device", &req.device], "session")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(parse_output(&output)))
}

pub async fn send_msg(
    State(state): State<AppState>,
    Json(req): Json<SendReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let output = run_echo(
        &state,
        &req.identity,
        &["send", "--to", &req.to, "-m", &req.message],
        "send",
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(parse_output(&output)))
}

pub async fn recv(
    State(state): State<AppState>,
    Json(req): Json<IdentityReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let output = run_echo(&state, &req.identity, &["recv"], "recv")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(parse_output(&output)))
}

pub async fn monitor(
    State(state): State<AppState>,
    Json(req): Json<IdentityReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let output = run_echo(&state, &req.identity, &["monitor"], "monitor")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let verified = output.contains("VERIFIED");
    let mut result = parse_output(&output);
    result
        .as_object_mut()
        .unwrap()
        .insert("verified".to_string(), serde_json::Value::Bool(verified));
    Ok(Json(result))
}

pub async fn read_state(
    State(state): State<AppState>,
    Json(req): Json<IdentityReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let identity_path = echo_dir(&req.identity).join("identity.json");

    state.emit(&req.identity, "state", "pending", "Reading identity state...");

    if !identity_path.exists() {
        state.emit(&req.identity, "state", "info", "No identity found");
        return Ok(Json(serde_json::json!({ "exists": false })));
    }

    let raw = tokio::fs::read_to_string(&identity_path)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let full: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Extract safe fields only — never expose private keys
    let safe = serde_json::json!({
        "exists": true,
        "account_id": full.get("account_id"),
        "device_id": full.get("device_id"),
        "identity_ed_public": truncate_key_array(full.get("identity_ed_public")),
        "identity_dh_public": truncate_key_array(full.get("identity_dh_public")),
        "signed_prekey_id": full.get("signed_prekey_id"),
        "pq_prekey_id": full.get("pq_prekey_id"),
        "otp_count": full.get("one_time_prekeys").and_then(|v| v.as_array()).map(|a| a.len()),
        "session_count": count_sessions(&req.identity),
    });

    state.emit(&req.identity, "state", "success", "State loaded");
    Ok(Json(safe))
}

pub async fn reset(
    State(state): State<AppState>,
    Json(req): Json<IdentityReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let dir = echo_dir(&req.identity);

    state.emit(&req.identity, "reset", "pending", &format!("Deleting {:?}", dir));

    if dir.exists() {
        tokio::fs::remove_dir_all(&dir)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        state.emit(&req.identity, "reset", "success", "Identity wiped");
    } else {
        state.emit(&req.identity, "reset", "info", "Nothing to delete");
    }

    Ok(Json(serde_json::json!({ "ok": true })))
}

// ── SSE log stream ───────────────────────────────────────────

pub async fn logs(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(entry) => {
            let data = serde_json::to_string(&entry).unwrap_or_default();
            Some(Ok(Event::default().data(data)))
        }
        Err(_) => None,
    });

    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("ping"),
    )
}

// ── Helpers ──────────────────────────────────────────────────

fn echo_dir(identity: &str) -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".echo")
        .join(identity)
}

fn count_sessions(identity: &str) -> usize {
    let sessions_dir = echo_dir(identity).join("sessions");
    if !sessions_dir.exists() {
        return 0;
    }
    std::fs::read_dir(sessions_dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.path()
                        .extension()
                        .map(|ext| ext == "json")
                        .unwrap_or(false)
                        && e.path()
                            .file_name()
                            .map(|n| n.to_string_lossy().contains(".meta."))
                            .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0)
}

fn truncate_key_array(val: Option<&serde_json::Value>) -> Option<String> {
    val.and_then(|v| v.as_array()).map(|arr| {
        let bytes: Vec<u8> = arr.iter().filter_map(|b| b.as_u64().map(|n| n as u8)).collect();
        let h = hex::encode(&bytes);
        if h.len() > 16 {
            format!("{}...", &h[..16])
        } else {
            h
        }
    })
}

fn parse_output(output: &str) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("raw".to_string(), serde_json::Value::String(output.trim().to_string()));

    // Extract key: value pairs from CLI output
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some((key, val)) = trimmed.split_once(':') {
            let key = key.trim().to_lowercase().replace(' ', "_");
            let val = val.trim().to_string();
            if !val.is_empty() {
                map.insert(key, serde_json::Value::String(val));
            }
        }
    }

    serde_json::Value::Object(map)
}
