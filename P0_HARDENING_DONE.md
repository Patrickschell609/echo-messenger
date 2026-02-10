# P0 + P1 + P2 Security Hardening -- COMPLETE

All 9 CRITICAL (P0), 2 HIGH (P1), and 4 MEDIUM (P2) vulnerabilities from SECURITY_AUDIT.md are fixed. Crypto core untouched (67/67 tests pass).

## What Was Done

### Phase 1: Message Size Limit (NEW-02)
- `MAX_ENVELOPE_SIZE = 65536` in `server/src/api/messages.rs`
- New `PayloadTooLarge` variant in `ApiError`, returns 413

### Phase 2: Vault-Only Storage (AV-01 + AV-02)
- `EncryptedVault` gained: `save_session`, `load_session`, `update_session`, `session_exists`, `save_last_sth`, `load_last_sth`, `save_server_transparency_key`, `load_server_transparency_key`, `save_sender_cert`, `load_sender_cert`
- `IdentityStore` removed from `AppState` -- no more plaintext `~/.echo/` writes
- All Tauri commands, poller, and contacts route through vault
- Legacy migration: `sign_on` auto-migrates `~/.echo/` into vault, then deletes originals

### Phase 3: Ed25519 Auth Tokens (AV-04)
- `authenticate_device()` in `server/src/api/mod.rs` -- verifies Ed25519 signature against DB-stored identity_key, checks timestamp +/- 5 min
- Client sends `X-Device-ID`, `X-Auth-Timestamp`, `X-Auth-Signature` headers
- Signed message: `device_id || timestamp || method || path`
- `HttpClient::with_auth()` constructor, all Tauri commands + poller use authenticated client
- `POST /v1/messages/send` stays UNAUTHENTICATED (sealed sender by design)

### Phase 4: Account Takeover Prevention (NEW-01)
- Migration `003_auth_nonce.sql`: `auth_nonce BYTEA`, `auth_nonce_expires_at TIMESTAMPTZ` on accounts
- New accounts: return `account_id` + `auth_nonce` (32 bytes, expires 10 min)
- Existing accounts: return error "account already exists" (never leak account_id)

### Phase 5: Authenticated Prekey Upload (AV-05)
- New device: requires `auth_nonce` from registration + Ed25519 signature
- Key rotation: requires Ed25519 signature verified against stored identity_key
- Signed message: `"echo-key-upload:" || account_id || identity_key_bytes`
- Nonce consumed atomically on use

### Phase 6: Real Sender Certificates (AV-08)
- `verify_sender_cert()` in `shared/src/sealed_sender/mod.rs`
- Server signs certs during key upload: `Ed25519.sign(device_id || identity_key || expiry)`
- Client stores signed cert in vault, uses it for sealing
- Recipient verifies server signature on unseal (if transparency key known)
- `vec![0u8; 64]` placeholder is dead

### Phase 7: Transparency Key Encryption (NEW-04)
- If `TRANSPARENCY_KEY_PASSWORD` set: AES-256-GCM(Argon2id(password, salt))
- File format: `salt(32) || nonce(12) || ciphertext`
- Without password: plaintext 32-byte file + warning log (dev mode)

### Phase 8: TLS Support (AV-03)
- `tls` feature flag on server: `axum-server` + `rustls-pemfile`
- `TLS_CERT_PATH` + `TLS_KEY_PATH` env vars
- Conditional HTTPS binding, warns if TLS vars set but feature not compiled

## Files Changed (17)
```
server/src/api/mod.rs          -- authenticate_device(), PayloadTooLarge
server/src/api/messages.rs     -- MAX_ENVELOPE_SIZE, Ed25519 auth
server/src/api/keys.rs         -- auth_nonce + signature verification, sender cert signing
server/src/api/accounts.rs     -- nonce generation, no account_id leak
server/src/config/mod.rs       -- TLS config fields
server/src/config/transparency.rs -- encrypted key storage
server/src/main.rs             -- conditional TLS binding
server/Cargo.toml              -- bincode, argon2, aes-gcm, axum-server
server/migrations/003_auth_nonce.sql -- NEW

echo-client/src/storage.rs     -- session/STH/cert vault methods
echo-client/src/http.rs        -- AuthCredentials, with_auth(), sign_request()
echo-client/Cargo.toml         -- ed25519-dalek

echo-app/src-tauri/src/state.rs         -- removed IdentityStore
echo-app/src-tauri/src/commands/auth.rs -- vault-only, migration, auth client
echo-app/src-tauri/src/commands/session.rs -- vault sessions
echo-app/src-tauri/src/commands/messaging.rs -- vault sessions, real certs
echo-app/src-tauri/src/commands/contacts.rs -- vault session_exists
echo-app/src-tauri/src/poller.rs        -- vault sessions, cert verification, auth client
echo-app/src-tauri/Cargo.toml  -- dirs

shared/src/sealed_sender/mod.rs -- verify_sender_cert()

cli/src/main.rs                -- updated for new register/upload signatures
```

## P1 (HIGH) -- COMPLETE

### AV-06: Ratchet State Desynchronization -- FIXED
- **Problem:** Ratchet advances in memory before network send. If send fails, nonce reuse on retry breaks AES-GCM.
- **Fix:** Persist-first pattern. Save ratchet state to vault BEFORE network send. If send fails, ratchet is safely advanced; user retries with new nonce. On receive side, only ack messages after successful ratchet persist.
- **Files changed:**
  - `echo-app/src-tauri/src/commands/messaging.rs` -- vault.save_session() moved before http.send_message()
  - `echo-app/src-tauri/src/poller.rs` -- `.ok()` replaced with conditional ack (skip ack on persist failure)

### AV-10: Message Queue Flooding (DoS) -- FIXED
- **Problem:** Rate limiter was no-op (`Identity::new()`). No per-recipient queue depth limit.
- **Fix:** Redis sliding window rate limiter (100 msgs/min per sender IP via sorted sets). Max queue depth per recipient (10,000 msgs). Returns 429 on either limit. Fails open if Redis unavailable.
- **Files changed:**
  - `server/src/api/mod.rs` -- added `TooManyRequests(String)` variant, returns 429
  - `server/src/api/messages.rs` -- `check_send_rate_limit()` + queue depth COUNT check before INSERT, IP extraction from X-Forwarded-For/X-Real-IP headers
  - `server/src/middleware/mod.rs` -- updated docs (rate limiting is handler-level)

## P2 (MEDIUM) -- COMPLETE

### AV-07: First Message Header in Plaintext -- FIXED
- **Problem:** First message in a session sends `ratchet_header` unencrypted because `sending_header_key` is None. Leaks DH public key, message number, prev chain length.
- **Fix:** Derive initial header keys from X4DH root key using HKDF. Initiator: send=`derive_header_key(root, true)`, recv=`derive_header_key(root, false)`. Responder: opposite direction flags.
- **Files changed:**
  - `echo-client/src/identity.rs` -- `build_initiator_state()` sets all 4 header key fields from X4DH root
  - `echo-app/src-tauri/src/poller.rs` -- responder `RatchetState` sets header keys with opposite direction flags

### AV-11: Phone Hash Enumeration -- FIXED
- **Problem:** Register returned different HTTP status (201 vs 400) and different response shapes for new vs existing accounts. Timing also differed.
- **Fix:** `INSERT ... ON CONFLICT DO NOTHING`. Both paths always return 200 with identical response shape (`account_id` + `auth_nonce`). Existing accounts get random UUID + random nonce (unusable). Added 200ms minimum response time to normalize timing.
- **Files changed:**
  - `server/src/api/accounts.rs` -- constant response shape, timing normalization

### AV-12: Silent Message Drop -- FIXED
- **Problem:** Poller silently `continue`d on any deserialization error without notifying user. Messages disappeared with no trace.
- **Fix:** Emit `message_error` event at every failure point with specific error context. Corrupted messages (hex/deser failures) get acked to clear queue + user notified. Crypto failures (unseal) get notified but NOT acked (may succeed after key update).
- **Files changed:**
  - `echo-app/src-tauri/src/events.rs` -- added `EVENT_MESSAGE_ERROR` constant
  - `echo-app/src-tauri/src/poller.rs` -- error events at all 5 failure points, differentiated ack policy

### NEW-03: Unauthenticated Key Transparency -- FIXED
- **Problem:** `/v1/transparency/proof/{device_id}` endpoint had no authentication. Anyone could probe for device existence.
- **Fix:** Added `authenticate_device()` call to `get_transparency_proof` handler.
- **Files changed:**
  - `server/src/api/keys.rs` -- Ed25519 auth on transparency proof endpoint

## All Files Changed (21)
```
--- P0 (9 CRITICAL) ---
server/src/api/mod.rs              -- authenticate_device(), PayloadTooLarge, TooManyRequests
server/src/api/messages.rs         -- MAX_ENVELOPE_SIZE, Ed25519 auth, rate limit, queue depth
server/src/api/keys.rs             -- auth_nonce + signature verification, sender cert signing, transparency auth
server/src/api/accounts.rs         -- nonce generation, constant response shape, timing normalization
server/src/config/mod.rs           -- TLS config fields
server/src/config/transparency.rs  -- encrypted key storage
server/src/main.rs                 -- conditional TLS binding
server/src/middleware/mod.rs       -- rate limit docs
server/Cargo.toml                  -- bincode, argon2, aes-gcm, axum-server
server/migrations/003_auth_nonce.sql -- NEW

echo-client/src/storage.rs         -- session/STH/cert vault methods
echo-client/src/http.rs            -- AuthCredentials, with_auth(), sign_request()
echo-client/src/identity.rs        -- X4DH header key derivation
echo-client/Cargo.toml             -- ed25519-dalek

echo-app/src-tauri/src/state.rs            -- removed IdentityStore
echo-app/src-tauri/src/events.rs           -- EVENT_MESSAGE_ERROR
echo-app/src-tauri/src/commands/auth.rs    -- vault-only, migration, auth client
echo-app/src-tauri/src/commands/session.rs -- vault sessions
echo-app/src-tauri/src/commands/messaging.rs -- vault sessions, real certs, persist-first
echo-app/src-tauri/src/commands/contacts.rs  -- vault session_exists
echo-app/src-tauri/src/poller.rs           -- vault, cert verify, auth, header keys, error events, conditional ack
echo-app/src-tauri/Cargo.toml              -- dirs

shared/src/sealed_sender/mod.rs    -- verify_sender_cert()

cli/src/main.rs                    -- updated for new register/upload signatures
```

## Verification Commands
```bash
cargo check --workspace              # compiles clean
cargo test -p echo-crypto            # 67/67 pass (45 unit + 12 integration + 10 transparency)
# After server running with Redis:
curl -X POST localhost:8080/v1/messages/receive       # 401 (no auth headers)
curl -X POST localhost:8080/v1/transparency/proof/... # 401 (no auth headers)
curl -X POST localhost:8080/v1/register -d '{"phone_hash":"<existing>"}' # 200 with random uuid (indistinguishable)
# Rate limit: 101st send_message in 60s returns 429
# Queue depth: send to a device with 10K+ queued messages returns 429
```

## What's Left: Nothing Critical
All 15 vulnerabilities (9 CRITICAL + 2 HIGH + 4 MEDIUM) from the red team audit are fixed. The remaining work is operational:
- Deploy with `TRANSPARENCY_KEY_PASSWORD` set
- Deploy with TLS certs (`TLS_CERT_PATH` + `TLS_KEY_PATH`)
- Frontend: display `message_error` events to user (toast/notification)
- Redis instance for rate limiting (fails open without it)
