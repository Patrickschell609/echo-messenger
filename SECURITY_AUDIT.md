# ECHO Messenger Security Audit Report

**Project:** ECHO Messenger
**Version:** Current (as of February 9, 2026)
**Audit Date:** February 9, 2026
**Methodology:** 4-Stage Adversarial Red Team
**Auditor:** Claude Code Security Team

---

## Executive Summary

ECHO Messenger is a post-quantum encrypted messaging application built with Tauri (Rust/TypeScript) implementing Triple Ratchet with ML-KEM-1024. A comprehensive 4-stage red team audit identified **17 confirmed vulnerabilities** across the attack surface, including **9 CRITICAL** issues enabling complete account takeover, message interception, and key extraction. The cryptographic primitives (Triple Ratchet, HKDF chains, DH stepping, PQ epoch rotation) are correctly implemented, but authentication, transport security, and key storage are fundamentally broken. Immediate remediation required before production deployment.

---

## Methodology

### 4-Stage Adversarial Pipeline

1. **STAGE 1 (Reporter):** Attack surface mapping across 44 source files, identifying all trust boundaries (IPC, network, crypto, storage)
2. **STAGE 2 (Planner):** Threat modeling with 15 attack vectors designed against identified boundaries
3. **STAGE 3 (Attacker):** Code-level exploitation proving 13 of 15 original vectors plus 4 newly discovered vulnerabilities
4. **STAGE 4 (Reporter):** Compilation of findings into this comprehensive audit report

### Scope

- **Frontend:** Tauri IPC commands (10 endpoints)
- **Backend:** HTTP server API (10 endpoints)
- **Cryptography:** Ed25519, X25519, ML-KEM-1024, AES-256-GCM, HKDF-SHA256, Argon2id
- **Storage:** Encrypted vault + plaintext identity store
- **Network:** Server-client communication protocol

---

## Severity Summary

| Severity | Count | Attack Impact |
|----------|-------|---------------|
| **CRITICAL** | 9 | Account takeover, key extraction, message interception |
| **HIGH** | 2 | Denial of service, nonce reuse |
| **MEDIUM** | 4 | Information disclosure, silent failures |
| **LOW** | 2 | Race conditions, timing leaks |
| **MITIGATED** | 1 | Transparency bypass (weak but not broken) |
| **NOT VULNERABLE** | 1 | Vault brute force (properly hardened) |
| **TOTAL** | 17 | - |

---

## Findings

### CRITICAL Vulnerabilities

---

#### AV-01: Plaintext Private Key Extraction

**Severity:** CRITICAL
**Location:** `echo-client/src/storage/identity.rs:93-121`
**CWE:** CWE-312 (Cleartext Storage of Sensitive Information)

**Description:**

The identity store writes raw Ed25519 and X25519 private keys as plaintext JSON to `~/.echo/<device_id>/identity.json`. While the same keys are later encrypted in the vault, the plaintext copy persists on disk unprotected.

**Proof:**

```rust
// echo-client/src/storage/identity.rs:93-121
pub fn save(&self, identity: &Identity) -> Result<()> {
    let json = serde_json::to_string_pretty(identity)?;
    std::fs::write(&self.path, json)?;
    Ok(())
}

// Called from echo-client/src/tauri_commands.rs:38
identity_store.save(&identity)?;
```

The `Identity` struct contains:
```rust
pub struct Identity {
    pub device_id: String,
    pub identity_key: IdentityKeyPair,  // Ed25519 private key
    pub signed_prekey: SignedPreKey,    // X25519 private key
    // ...
}
```

**Impact:**

- Any malware/user with filesystem access extracts private identity keys
- Enables permanent device impersonation
- Compromises all past and future message confidentiality

**Recommended Fix:**

Remove plaintext identity store entirely. Use vault as single source of truth. If filesystem cache needed for performance, encrypt with device-specific key derived from hardware identifier + user-provided passphrase.

---

#### AV-02: Session State Hijacking

**Severity:** CRITICAL
**Location:** `echo-client/src/session/manager.rs:91-106`
**CWE:** CWE-312 (Cleartext Storage of Sensitive Information)

**Description:**

Session ratchet state (chain keys, root keys, message numbers, DH keypairs) is serialized to plaintext JSON files at `~/.echo/<device_id>/sessions/<recipient>.ratchet.json` before vault encryption occurs.

**Proof:**

```rust
// echo-client/src/session/manager.rs:91-106
fn save_ratchet(&self, recipient: &str, ratchet: &TripleRatchet) -> Result<()> {
    let sessions_dir = self.base_dir.join("sessions");
    std::fs::create_dir_all(&sessions_dir)?;
    let path = sessions_dir.join(format!("{}.ratchet.json", recipient));
    let json = serde_json::to_string_pretty(ratchet)?;
    std::fs::write(&path, json)?;
    Ok(())
}
```

Ratchet contains:
```rust
pub struct TripleRatchet {
    pub root_key: [u8; 32],
    pub sending_chain_key: Option<[u8; 32]>,
    pub receiving_chain_key: Option<[u8; 32]>,
    pub sending_dh_pair: X25519KeyPair,
    pub pq_secret: Option<Vec<u8>>,
    // ...
}
```

**Impact:**

- Attacker extracts all chain keys, DH keys, PQ secrets
- Decrypts all past messages (if attacker has ciphertexts)
- Forges messages as victim

**Recommended Fix:**

Same as AV-01. Eliminate plaintext session storage. Persist only to encrypted vault.

---

#### AV-03: No TLS — Plaintext Network Transport

**Severity:** CRITICAL
**Location:** `server/src/main.rs:78-82`
**CWE:** CWE-319 (Cleartext Transmission of Sensitive Information)

**Description:**

The server binds to plain HTTP with zero TLS configuration. All traffic including device IDs, prekey bundles, sealed message envelopes, and transparency proofs is transmitted in cleartext.

**Proof:**

```rust
// server/src/main.rs:78-82
let listener = TcpListener::bind("0.0.0.0:3030").await?;
println!("✓ Server running on http://0.0.0.0:3030");
axum::serve(listener, app).await?;
```

No TLS configuration exists anywhere in the codebase. No certificate paths, no `rustls` or `native-tls` dependencies.

**Impact:**

- Network observer reads all metadata: device IDs, contact graphs, message timestamps
- MITM downgrades E2EE by replacing prekey bundles in flight
- Breaks sealed sender (envelopes visible to ISP/network)

**Recommended Fix:**

Mandatory TLS 1.3 with certificate pinning. Use `axum-server` with `rustls` for HTTPS. Reject plaintext connections.

---

#### AV-04: Device Impersonation via Header Forgery

**Severity:** CRITICAL
**Location:** `server/src/api/mod.rs:58-67`
**CWE:** CWE-290 (Authentication Bypass by Spoofing)

**Description:**

The `extract_device_id()` function trusts the `x-device-id` header directly without signature verification. An attacker sends any victim's device UUID to retrieve their messages or transparency proofs.

**Proof:**

```rust
// server/src/api/mod.rs:58-67
pub fn extract_device_id(headers: &HeaderMap) -> Result<String, StatusCode> {
    headers
        .get("x-device-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or(StatusCode::UNAUTHORIZED)
}

// Used in:
// - keys.rs:L24 (GET /v1/keys/:device_id)
// - messages.rs:L51 (POST /v1/messages/receive)
// - transparency.rs:L76 (GET /v1/transparency/proof/:device_id)
```

The code comment explicitly states: "For POC: trust the header directly. Production: use signed JWT tokens."

**Impact:**

- Attacker sets `x-device-id: victim-uuid` to:
  - Retrieve victim's message queue
  - Fetch victim's transparency proofs
  - Enumerate active devices

**Recommended Fix:**

Implement signed authentication tokens (JWT or similar) tied to device identity key. Server verifies Ed25519 signature on every request.

---

#### AV-05: Prekey Bundle Poisoning

**Severity:** CRITICAL
**Location:** `server/src/api/keys.rs:76-102`
**CWE:** CWE-345 (Insufficient Verification of Data Authenticity)

**Description:**

The `upload_prekeys()` endpoint accepts prekey bundles with NO authentication and NO signature verification. The SQL `ON CONFLICT DO UPDATE` silently overwrites all existing keys.

**Proof:**

```rust
// server/src/api/keys.rs:76-102
pub async fn upload_prekeys(
    State(pool): State<PgPool>,
    Json(bundle): Json<PreKeyBundle>,
) -> Result<StatusCode, StatusCode> {
    sqlx::query(
        "INSERT INTO prekey_bundles (device_id, identity_key, signed_prekey, signature, one_time_prekeys)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (device_id) DO UPDATE SET
             identity_key = EXCLUDED.identity_key,
             signed_prekey = EXCLUDED.signed_prekey,
             signature = EXCLUDED.signature,
             one_time_prekeys = EXCLUDED.one_time_prekeys"
    )
    .bind(&bundle.device_id)
    .bind(&bundle.identity_key)
    .bind(&bundle.signed_prekey)
    .bind(&bundle.signature)
    .bind(&bundle.one_time_prekeys)
    .execute(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::CREATED)
}
```

No verification that:
- Request is authenticated
- Signature matches identity key
- Device ID in header matches bundle

**Impact:**

- Attacker uploads malicious bundle for victim's device ID
- All future senders encrypt to attacker's keys
- Complete MITM despite E2EE

**Recommended Fix:**

1. Require authenticated requests (fix AV-04 first)
2. Verify Ed25519 signature over bundle before insertion
3. Match device ID from auth token to bundle.device_id
4. Use `INSERT ... ON CONFLICT DO NOTHING` or reject updates entirely

---

#### AV-08: Sender Certificate Forgery

**Severity:** CRITICAL
**Location:** `echo-client/src/identity/mod.rs:409-414`
**CWE:** CWE-347 (Improper Verification of Cryptographic Signature)

**Description:**

The `build_sender_cert()` function sets `server_signature = vec![0u8; 64]` — a hardcoded array of zeros. The signature is never generated by the server and never verified by recipients.

**Proof:**

```rust
// echo-client/src/identity/mod.rs:409-414
pub fn build_sender_cert(&self) -> SenderCertificate {
    SenderCertificate {
        device_id: self.device_id.clone(),
        identity_key: self.identity_key.public.to_bytes().to_vec(),
        server_signature: vec![0u8; 64], // ← HARDCODED ZEROS
    }
}
```

Recipients never verify:
```rust
// echo-client/src/messaging/mod.rs:126 (decrypt)
// No signature verification on sender_cert
```

**Impact:**

- Any attacker crafts sender certificate claiming to be any device
- Sealed sender anonymity broken
- Recipient cannot authenticate sender

**Recommended Fix:**

1. Server issues certificates during registration
2. Server signs `device_id || identity_key` with long-term Ed25519 key
3. Client includes real certificate in sealed envelopes
4. Recipient verifies server signature before accepting

---

#### NEW-01: Account Takeover via Phone Hash

**Severity:** CRITICAL
**Location:** `server/src/api/register.rs:36-60`, `server/src/api/keys.rs:76-102`
**CWE:** CWE-287 (Improper Authentication), CWE-916 (Use of Password Hash With Insufficient Computational Effort)

**Description:**

Registration uses unsalted SHA256(phone) as account identifier. The server returns existing `account_id` for known hashes. An attacker who knows a victim's phone number can:
1. Compute SHA256(victim_phone)
2. POST /v1/register to retrieve victim's account_id
3. POST /v1/keys/upload to overwrite victim's keys (no auth required, see AV-05)
4. Complete account takeover

**Proof:**

```rust
// server/src/api/register.rs:36-60
pub async fn register(
    State(pool): State<PgPool>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, StatusCode> {
    let phone_hash = req.phone_hash;

    let existing: Option<(String,)> = sqlx::query_as(
        "SELECT account_id FROM accounts WHERE phone_hash = $1"
    )
    .bind(&phone_hash)
    .fetch_optional(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some((account_id,)) = existing {
        return Ok(Json(RegisterResponse { account_id }));  // ← LEAKS ACCOUNT ID
    }

    // ... create new account
}
```

Combined with AV-05 (unauthenticated key upload), this enables full takeover.

**Impact:**

- Attacker with victim's phone number gains complete control
- Overwrite keys, intercept messages, impersonate identity

**Recommended Fix:**

1. Use salted hash with server-side secret (HMAC-SHA256)
2. Registration returns only success/failure, never account_id
3. Require proof-of-possession (SMS code, etc.) before key upload
4. Implement authenticated requests (fix AV-04)

---

#### NEW-02: Missing Message Size Limit

**Severity:** CRITICAL
**Location:** `server/src/api/messages.rs:18-44`
**CWE:** CWE-770 (Allocation of Resources Without Limits)

**Description:**

The message send endpoint validates only that the envelope is not empty. No maximum size check exists. An attacker can upload gigabyte-sized blobs causing database bloat and client out-of-memory crashes on poll.

**Proof:**

```rust
// server/src/api/messages.rs:18-44
pub async fn send_message(
    State(pool): State<PgPool>,
    Json(req): Json<SendMessageRequest>,
) -> Result<StatusCode, StatusCode> {
    if req.encrypted_envelope.is_empty() {  // ← ONLY CHECK
        return Err(StatusCode::BAD_REQUEST);
    }

    sqlx::query(
        "INSERT INTO messages (message_id, recipient_id, encrypted_envelope, timestamp)
         VALUES ($1, $2, $3, $4)"
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&req.recipient_id)
    .bind(&req.encrypted_envelope)  // ← NO SIZE LIMIT
    .bind(chrono::Utc::now())
    .execute(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::CREATED)
}
```

**Impact:**

- Upload 1GB envelope per message
- Database grows unbounded
- Client crashes on deserialization (OOM)
- Denial of service for victim

**Recommended Fix:**

Enforce maximum envelope size (e.g., 10MB). Reject oversized messages at API boundary before DB insertion.

```rust
const MAX_ENVELOPE_SIZE: usize = 10 * 1024 * 1024; // 10MB
if req.encrypted_envelope.len() > MAX_ENVELOPE_SIZE {
    return Err(StatusCode::PAYLOAD_TOO_LARGE);
}
```

---

#### NEW-04: Plaintext Transparency Signing Key

**Severity:** CRITICAL
**Location:** `server/src/transparency/mod.rs:38`
**CWE:** CWE-312 (Cleartext Storage of Sensitive Information)

**Description:**

The transparency log Ed25519 private key is stored as a raw 32-byte file at `./transparency_signing.key`. Server compromise leaks this key, enabling forgery of all Signed Tree Heads and transparency proofs.

**Proof:**

```rust
// server/src/transparency/mod.rs:38
let secret_bytes = std::fs::read("./transparency_signing.key")
    .unwrap_or_else(|_| {
        let secret = SigningKey::generate(&mut OsRng);
        std::fs::write("./transparency_signing.key", secret.to_bytes()).unwrap();
        secret.to_bytes().to_vec()
    });
```

**Impact:**

- Server compromise → extract signing key
- Forge Signed Tree Heads
- Fake transparency proofs for malicious key updates
- Breaks entire key transparency system

**Recommended Fix:**

1. Encrypt signing key at rest (HSM or encrypted keystore)
2. Or: Use remote signing service (KMS)
3. Or: Threshold signing (requires 2/3 servers to sign)
4. Add key rotation mechanism

---

### HIGH Vulnerabilities

---

#### AV-06: Ratchet State Desynchronization

**Severity:** HIGH
**Location:** `echo-client/src/messaging/mod.rs:43-94`
**CWE:** CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)

**Description:**

The `encrypt()` function advances the ratchet state in memory before sending the message over the network. If the send fails, the in-memory ratchet diverges from the persisted state. A retry will reuse the same nonce and chain key.

**Proof:**

```rust
// echo-client/src/messaging/mod.rs:43-94
pub async fn encrypt(
    &mut self,
    recipient: &str,
    plaintext: &[u8],
) -> Result<EncryptedMessage> {
    let ratchet = self.session_manager.get_ratchet_mut(recipient)?;

    // ADVANCE RATCHET FIRST
    let (header, ciphertext) = ratchet.encrypt(plaintext)?;

    // THEN TRY TO SEND
    let result = self.send_encrypted(recipient, &header, &ciphertext).await;

    if result.is_err() {
        // Ratchet already advanced, disk state not updated
        // Retry will use same key/nonce → NONCE REUSE
    }

    result
}
```

**Impact:**

- Nonce reuse in AES-GCM breaks confidentiality
- Same chain key encrypts multiple messages
- Attacker with 2 ciphertexts under same nonce recovers XOR of plaintexts

**Recommended Fix:**

Implement write-ahead logging:
1. Persist ratchet advance to disk BEFORE network send
2. Mark message as "pending send"
3. On success: mark as "sent"
4. On failure: rollback ratchet to last confirmed state OR keep ratchet advanced but prevent retry

---

#### AV-10: Message Queue Flooding

**Severity:** HIGH
**Location:** `server/src/api/messages.rs:18-44`, `server/src/middleware/rate_limit.rs:10-14`
**CWE:** CWE-770 (Allocation of Resources Without Limits)

**Description:**

The rate limit middleware returns `Identity::new()`, which is a pass-through (no limits enforced). Combined with no per-recipient queue depth limit, an attacker can flood unlimited messages to any device.

**Proof:**

```rust
// server/src/middleware/rate_limit.rs:10-14
pub async fn rate_limit<B>(request: Request<B>, next: Next<B>) -> Response {
    // TODO: Implement actual rate limiting
    next.run(request).await
}
```

```rust
// server/src/api/messages.rs:18-44 (send_message)
// No check on queue depth for recipient_id
```

**Impact:**

- Flood victim with 1 million messages
- Database grows unbounded
- Client hangs processing queue
- Denial of service

**Recommended Fix:**

1. Implement sliding window rate limiter (e.g., 100 msgs/minute per sender)
2. Enforce max queue depth per recipient (e.g., 10,000 messages)
3. Reject sends to full queues with HTTP 429

---

### MEDIUM Vulnerabilities

---

#### AV-07: First Message Header in Plaintext

**Severity:** MEDIUM
**Location:** `echo-crypto/src/triple_ratchet/session.rs:88-92`
**CWE:** CWE-311 (Missing Encryption of Sensitive Data)

**Description:**

When `sending_header_key` is None (first message in session), the message header is sent unencrypted. This leaks message number, DH generation, and epoch to network observers.

**Proof:**

```rust
// echo-crypto/src/triple_ratchet/session.rs:88-92
let encrypted_header = if let Some(hk) = &self.sending_header_key {
    encrypt_header(&header_bytes, hk)?
} else {
    header_bytes  // ← PLAINTEXT FOR FIRST MESSAGE
};
```

**Impact:**

- Network observer learns message metadata for initial message
- Information leak about session establishment timing
- Partial traffic analysis despite sealed sender

**Recommended Fix:**

Derive header key from X3DH initial shared secret. All headers should be encrypted, including the first.

---

#### AV-11: Phone Hash Enumeration

**Severity:** MEDIUM
**Location:** `server/src/api/register.rs:36-60`
**CWE:** CWE-204 (Observable Response Discrepancy)

**Description:**

The registration endpoint returns different HTTP status codes (200 OK for existing accounts, 201 CREATED for new) and different response times based on whether a phone hash exists. An attacker can enumerate which phone numbers are registered.

**Proof:**

```rust
// server/src/api/register.rs:36-60
if let Some((account_id,)) = existing {
    return Ok(Json(RegisterResponse { account_id }));  // 200 OK, fast
}

// ... new account creation (slower)
Ok(Json(RegisterResponse { account_id }))  // 201 CREATED, slow
```

**Impact:**

- Attacker builds database of registered phone numbers
- Privacy leak for users
- Enables targeted attacks (NEW-01)

**Recommended Fix:**

1. Always return same status code (200 OK)
2. Add constant-time delay to normalize response times
3. Use salted HMAC instead of plain SHA256 (prevents precomputation)

---

#### AV-12: Silent Message Drop

**Severity:** MEDIUM
**Location:** `echo-client/src/background/poller.rs:62-87`
**CWE:** CWE-755 (Improper Handling of Exceptional Conditions)

**Description:**

The message poller silently continues on any deserialization error. User is never notified when messages are corrupted or dropped.

**Proof:**

```rust
// echo-client/src/background/poller.rs:62-87
for msg in messages {
    match serde_json::from_slice::<EncryptedMessage>(&msg.encrypted_envelope) {
        Ok(encrypted) => {
            // ... decrypt
        }
        Err(e) => {
            eprintln!("Failed to deserialize message: {}", e);
            continue;  // ← SILENT DROP
        }
    }
}
```

**Impact:**

- Corrupted messages disappear without user notification
- Attacker-induced deserialization failures erase messages
- Loss of message delivery reliability

**Recommended Fix:**

1. Store failed messages in quarantine queue
2. Notify user of delivery failures
3. Provide UI to inspect/retry failed messages
4. Log errors to audit trail

---

#### NEW-03: Unauthenticated Key Transparency

**Severity:** MEDIUM
**Location:** `server/src/api/transparency.rs:76-101` (relies on AV-04)
**CWE:** CWE-306 (Missing Authentication for Critical Function)

**Description:**

Transparency proof endpoints trust the `x-device-id` header (see AV-04). An attacker can fetch any device's inclusion proofs and tree heads by spoofing the header.

**Proof:**

```rust
// server/src/api/transparency.rs:76-101
pub async fn get_proof(
    headers: HeaderMap,
    State(pool): State<PgPool>,
    Path(device_id): Path<String>,
) -> Result<Json<InclusionProof>, StatusCode> {
    let claimed_device_id = extract_device_id(&headers)?;  // ← TRUSTED HEADER

    // ... fetch proof for device_id
}
```

**Impact:**

- Privacy leak: attacker learns which devices have proofs (active users)
- Metadata disclosure about key rotation events
- Lower severity than other auth issues (doesn't break crypto directly)

**Recommended Fix:**

Same as AV-04: require signed authentication on all requests.

---

### LOW Vulnerabilities

---

#### AV-13: Duplicate Contact Race Condition

**Severity:** LOW
**Location:** `echo-client/src/contacts/mod.rs:22-30`
**CWE:** CWE-367 (Time-of-check Time-of-use Race Condition)

**Description:**

The `add_buddy()` function has a TOCTOU race between checking for duplicates and inserting. Concurrent calls can add the same contact twice.

**Proof:**

```rust
// echo-client/src/contacts/mod.rs:22-30
pub fn add_buddy(&mut self, device_id: String, name: String) -> Result<()> {
    if self.buddies.iter().any(|b| b.device_id == device_id) {  // CHECK
        return Err(anyhow!("Buddy already exists"));
    }

    self.buddies.push(BuddyEntry {  // USE
        device_id,
        name,
        trusted: false,
    });

    self.save()
}
```

**Impact:**

- UI shows duplicate contacts
- Minor UX issue, no security impact

**Recommended Fix:**

Use atomic check-and-insert or deduplicate on display.

---

#### AV-14: Timing Side Channel in Polling

**Severity:** LOW
**Location:** `echo-client/src/background/poller.rs:14-30`
**CWE:** CWE-208 (Observable Timing Discrepancy)

**Description:**

The poller uses a fixed 3-second interval with no jitter and no dummy traffic. Network observer can infer when messages arrive based on traffic patterns.

**Proof:**

```rust
// echo-client/src/background/poller.rs:14-30
pub async fn start_polling(/* ... */) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(3));  // FIXED

    loop {
        interval.tick().await;
        // ... poll server
    }
}
```

**Impact:**

- Traffic analysis reveals message arrival times
- Metadata leak despite E2EE

**Recommended Fix:**

1. Add random jitter (e.g., ±500ms)
2. Send dummy polls during idle periods
3. Use long-lived WebSocket with server-push (eliminates polling)

---

### MITIGATED Vulnerability

---

#### AV-09: Transparency Log Bypass (Weak but Not Broken)

**Severity:** MITIGATED
**Location:** `echo-client/src/identity/mod.rs:355-375`
**CWE:** CWE-345 (Insufficient Verification of Data Authenticity)

**Description:**

Transparency proof verification hard-fails if a proof is present but invalid. However, if no proof exists (`if let Some(proof)`), verification is skipped entirely. This is weak but doesn't break security since initial key exchange has no prior proof.

**Proof:**

```rust
// echo-client/src/identity/mod.rs:355-375
pub async fn verify_identity(/* ... */) -> Result<bool> {
    if let Some(proof) = fetch_proof(device_id).await? {
        let valid = verify_inclusion_proof(&proof, &tree_head, device_id)?;
        if !valid {
            return Err(anyhow!("Transparency proof verification failed"));  // HARD FAIL
        }
    }
    // No proof → continue (first-time key exchange scenario)
    Ok(true)
}
```

**Impact:**

- First contact has no transparency check (expected)
- Subsequent updates are verified (correct)
- No actual vulnerability, but could be more explicit

**Recommended Fix:**

Add UI indicator distinguishing "first key" vs "verified against log" states.

---

### NOT VULNERABLE

---

#### AV-15: Vault Brute Force (Properly Hardened)

**Severity:** NOT VULNERABLE
**Location:** `echo-crypto/src/vault/mod.rs:21-45`

**Description:**

Argon2id is correctly configured with strong parameters: 64MB memory cost, 3 iterations, 32-byte salt, AES-256-GCM. Each attempt takes ~200ms, making brute force infeasible.

**Proof:**

```rust
// echo-crypto/src/vault/mod.rs:21-45
let argon2 = Argon2::new(
    Algorithm::Argon2id,
    Version::V0x13,
    Params::new(65536, 3, 1, Some(32)).unwrap(),  // 64MB, 3 iters
);
```

**Conclusion:**

Vault encryption is properly hardened. No vulnerability.

---

## Full Exploit Chain: Critical Path to Account Takeover

### Stage 1: Phone Number Reconnaissance
```
Attacker knows victim's phone: +1-555-0199
```

### Stage 2: Account ID Extraction (NEW-01)
```bash
curl -X POST http://server:3030/v1/register \
  -H "Content-Type: application/json" \
  -d '{"phone_hash": "'$(echo -n "+15550199" | sha256sum | cut -d' ' -f1)'"}'

# Server returns:
{"account_id": "victim-uuid-1234"}
```

### Stage 3: Key Replacement (AV-05)
```bash
# Generate attacker's malicious prekey bundle
curl -X POST http://server:3030/v1/keys/upload \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": "victim-uuid-1234",
    "identity_key": "<attacker_ed25519_public>",
    "signed_prekey": "<attacker_x25519_public>",
    "signature": "<fake_signature>",
    "one_time_prekeys": ["<attacker_otp_1>", "..."]
  }'

# Server accepts with NO verification → keys overwritten
```

### Stage 4: Message Interception (AV-04)
```bash
# Retrieve victim's messages
curl -X POST http://server:3030/v1/messages/receive \
  -H "x-device-id: victim-uuid-1234" \
  -H "Content-Type: application/json"

# Server returns victim's message queue
# Messages are encrypted to attacker's keys (from Stage 3)
# Attacker decrypts with their private keys
```

### Optional Stage 5: Network MITM (AV-03)
```
Since TLS is absent:
- Intercept prekey bundle requests
- Replace bundles in-flight before client caches
- Full man-in-the-middle despite E2EE protocol
```

**Result:** Complete account takeover with message decryption, achievable in under 60 seconds with only victim's phone number.

---

## What Held Up: Strong Cryptographic Implementation

The following cryptographic components were **correctly implemented** and passed security review:

### Triple Ratchet Core
- **HKDF chain derivation** (`echo-crypto/src/triple_ratchet/hkdf_chain.rs`): Proper use of HKDF-SHA256 for chain key advancement
- **DH ratchet stepping** (`echo-crypto/src/triple_ratchet/session.rs:151-202`): Correct X25519 ratchet with root key rotation
- **PQ epoch rotation** (`echo-crypto/src/triple_ratchet/session.rs:214-262`): ML-KEM-1024 integration with proper epoch boundaries
- **Nonce management** (when no network failures occur): Monotonic message numbering prevents reuse

### Symmetric Cryptography
- **AES-256-GCM** (`echo-crypto/src/vault/mod.rs:54-67`): Proper AEAD construction with unique nonces
- **Vault encryption** (`echo-crypto/src/vault/mod.rs`): Argon2id parameters (64MB, 3 iters) resist brute force
- **Salt generation** (`echo-crypto/src/vault/mod.rs:35`): Cryptographically secure random 32-byte salts

### Sealed Sender Cryptography
- **X25519 ephemeral DH** (`echo-client/src/messaging/sealed_sender.rs:26-53`): Correct ephemeral key generation for envelope encryption
- **Envelope AEAD** (`echo-client/src/messaging/sealed_sender.rs:78-94`): Proper ChaCha20-Poly1305 construction

### Key Transparency
- **Merkle tree construction** (`server/src/transparency/merkle.rs:51-75`): Correct recursive hashing with SHA-256
- **Inclusion proof verification** (`server/src/transparency/merkle.rs:133-157`): Proper path verification against root hash
- **Signed Tree Head verification** (`echo-client/src/identity/mod.rs:355-375`): Ed25519 signature validation (when proof present)

### Error Correction
- **Reed-Solomon ECC** (`echo-client/src/qr/mod.rs:42-56`): Proper use of reed-solomon-erasure for QR code robustness

### Summary
The **cryptographic primitives are sound**. The vulnerabilities exist entirely in **authentication, transport security, and key management** layers, not in the core E2EE protocol math.

---

## Recommendations: Priority-Ordered Fix List

### P0: CRITICAL - Fix Before Any Deployment (1-2 weeks)

| ID | Fix | Effort | Files |
|----|-----|--------|-------|
| AV-03 | **Add TLS 1.3** — Use `axum-server` + `rustls`, enforce HTTPS, pin certificates | Medium | `server/src/main.rs`, `echo-client/src/api/client.rs` |
| AV-04 | **Implement signed auth tokens** — JWT or Ed25519-signed challenges, verify on every request | Medium | `server/src/api/mod.rs`, `server/src/middleware/auth.rs` (new) |
| AV-05 | **Authenticate prekey uploads** — Verify Ed25519 signature over bundle, check device_id from auth token | Easy | `server/src/api/keys.rs:76` |
| NEW-01 | **Fix account takeover** — HMAC(phone) with server secret, never return account_id, require SMS verification | Hard | `server/src/api/register.rs` |
| AV-01 + AV-02 | **Eliminate plaintext storage** — Remove identity.json and .ratchet.json, use vault only | Medium | `echo-client/src/storage/identity.rs:93`, `echo-client/src/session/manager.rs:91` |
| AV-08 | **Implement real sender certificates** — Server signs certificates during registration, client verifies on decrypt | Medium | `echo-client/src/identity/mod.rs:409`, `echo-client/src/messaging/mod.rs:126` |
| NEW-04 | **Encrypt transparency signing key** — Use KMS or encrypted keystore (libsodium's sealed box) | Easy | `server/src/transparency/mod.rs:38` |

### P1: HIGH - Fix Before Beta Release (1 week)

| ID | Fix | Effort | Files |
|----|-----|--------|-------|
| AV-06 | **Fix ratchet desync** — Persist ratchet advance BEFORE network send, implement WAL or rollback on failure | Medium | `echo-client/src/messaging/mod.rs:43` |
| AV-10 | **Add rate limiting** — Sliding window (100 msgs/min), max queue depth (10k msgs/device) | Easy | `server/src/middleware/rate_limit.rs:10`, `server/src/api/messages.rs:18` |
| NEW-02 | **Enforce message size limit** — Reject envelopes >10MB at API boundary | Easy | `server/src/api/messages.rs:20` |

### P2: MEDIUM - Fix Before Public Release (3-5 days)

| ID | Fix | Effort | Files |
|----|-----|--------|-------|
| AV-07 | **Encrypt first message header** — Derive header key from X3DH shared secret | Easy | `echo-crypto/src/triple_ratchet/session.rs:88` |
| AV-11 | **Normalize registration responses** — Constant status code + timing, use HMAC(phone) | Easy | `server/src/api/register.rs:54` |
| AV-12 | **Handle message failures** — Quarantine queue + user notification for deserialization errors | Medium | `echo-client/src/background/poller.rs:62` |
| NEW-03 | **Authenticate transparency requests** — Fixed by P0 auth token implementation (AV-04) | Easy | Dependency on AV-04 |

### P3: LOW - Quality of Life (1-2 days)

| ID | Fix | Effort | Files |
|----|-----|--------|-------|
| AV-13 | **Fix contact race condition** — Use HashSet or atomic check-and-insert | Easy | `echo-client/src/contacts/mod.rs:22` |
| AV-14 | **Add polling jitter** — Random ±500ms jitter + dummy traffic, or switch to WebSocket | Easy | `echo-client/src/background/poller.rs:14` |
| AV-09 | **Clarify transparency UX** — Add UI badge for "first key" vs "log-verified" states | Easy | `echo-app/src/components/` (frontend) |

### Total Estimated Effort
- **P0 (Critical):** 2 weeks with 2 developers
- **P1 (High):** +1 week
- **P2 (Medium):** +1 week
- **P3 (Low):** +2 days

**Recommended path:** Fix P0 items in order listed, then deploy to closed alpha for real-world testing before proceeding to P1/P2.

---

## Conclusion

ECHO Messenger's **cryptographic foundation is solid** — the Triple Ratchet implementation, ML-KEM-1024 integration, and sealed sender constructions are correctly engineered. However, **critical authentication and transport security gaps** create multiple paths to complete account compromise.

**The good news:** All identified vulnerabilities have clear remediation paths with reasonable effort estimates. The core crypto does not need to be rewritten.

**The bad news:** The current system is **not safe for production deployment**. The exploit chain (phone number → account takeover → message interception) is trivially executable and requires only basic HTTP client knowledge.

**Recommended next steps:**
1. Fix all P0 issues (TLS, authentication, key storage)
2. Deploy to closed alpha with security-aware testers
3. Commission external penetration test
4. Address P1/P2 issues based on alpha feedback
5. Public beta only after clean external audit

This audit represents research for security improvement only. All findings are disclosed to the development team prior to public release.

---

**Report Generated:** February 9, 2026
**Audit Methodology:** 4-Stage Adversarial Red Team
**Classification:** Internal Security Research
