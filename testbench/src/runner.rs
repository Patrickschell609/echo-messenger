use anyhow::{Context, Result};
use tokio::process::Command;

use crate::state::AppState;

/// Run an echo CLI command and stream output as log entries.
/// Returns the raw stdout on success.
pub async fn run_echo(
    state: &AppState,
    identity: &str,
    args: &[&str],
    label: &str,
) -> Result<String> {
    state.emit(identity, label, "pending", &format!("Running: echo -i {identity} {}", args.join(" ")));

    let output = Command::new(state.echo_bin())
        .arg("-i")
        .arg(identity)
        .arg("--server")
        .arg(state.server_url())
        .args(args)
        .output()
        .await
        .context("Failed to spawn echo CLI")?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // Stream each stdout line as a log entry
    for line in stdout.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            state.emit(identity, label, "info", trimmed);
        }
    }

    if !output.status.success() {
        let err_msg = if stderr.is_empty() {
            format!("Exit code: {}", output.status)
        } else {
            stderr.trim().to_string()
        };
        // Log stderr lines
        for line in err_msg.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                state.emit(identity, label, "error", trimmed);
            }
        }
        anyhow::bail!("{err_msg}");
    }

    state.emit(identity, label, "success", &format!("{label} completed"));
    Ok(stdout)
}
