use tower::layer::util::Identity;

/// Returns a global middleware layer (pass-through).
///
/// Per-endpoint rate limiting is handled at the handler level:
/// - `send_message`: Redis sliding window (100/min per IP) + queue depth (10K per recipient)
/// - Authenticated endpoints: Ed25519 signatures provide natural DoS resistance
pub fn rate_limit_layer() -> Identity {
    Identity::new()
}
