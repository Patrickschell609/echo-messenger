# ECHO Messenger — Handoff Notes

## What This Is

Post-quantum secure messenger with Triple Ratchet (TR3) protocol, sealed sender anonymity, and zero-knowledge server design. Think Signal but with an added post-quantum ratchet layer (ML-KEM-1024) on top of the standard Double Ratchet.

**Status:** POC working end-to-end. Alice and Bob can register, establish sessions, and exchange encrypted messages through a live server. All crypto layers are active.

**Lines of code:** ~4,300 Rust + ~2,200 Dart across 35 client files.

---

## Architecture

```
┌─────────────┐         ┌─────────────────┐         ┌─────────────┐
│  echo-cli   │  HTTP   │   echo-server   │  HTTP   │  echo-cli   │
│  (Alice)    │────────>│   (Axum/PG)     │<────────│  (Bob)      │
│             │         │                 │         │             │
│ X4DH + TR3  │         │ Zero-knowledge  │         │ X4DH + TR3  │
│ Sealed Send │         │ Just routes     │         │ Sealed Send │
└─────────────┘         │ opaque blobs    │         └─────────────┘
                        └─────────────────┘
┌──────────────────┐           ▲
│  Flutter Client  │───────────┘ HTTP (dio)
│  (Android)       │
│                  │──── FFI ──── shared/src/ffi_api.rs
│  Riverpod + UI   │             (flutter_rust_bridge v2)
│  sqflite + keys  │
└──────────────────┘
```

Three Rust crates in one workspace + Flutter client:

| Crate / Module | Path | Purpose |
|----------------|------|---------|
| `echo-crypto` | `shared/` | Crypto core — TR3, X4DH, sealed sender, FFI API |
| `echo-server` | `server/` | Axum REST API, PostgreSQL, message queue |
| `echo-cli` | `cli/` | CLI client for POC testing |
| Flutter client | `client/` | Android app — Riverpod, sqflite, Rust FFI |

---

## Crypto Stack

### Triple Ratchet (3 layers)

| Layer | Mechanism | Ratchets When |
|-------|-----------|---------------|
| 1 - Symmetric | HKDF-SHA256 chain | Every message |
| 2 - DH | X25519 Diffie-Hellman | Every turn (direction change) |
| 3 - PQ | ML-KEM-1024 KEM | Every 100 messages OR 24 hours |

### Session Establishment (X4DH)

Extended X3DH with 4 DH operations + PQ KEM:

```
DH1 = DH(IK_A_dh, SPK_B)       — identity DH to signed prekey
DH2 = DH(EK_A, IK_B_dh)        — ephemeral to identity DH
DH3 = DH(EK_A, SPK_B)          — ephemeral to signed prekey
DH4 = DH(EK_A, OPK_B)          — ephemeral to one-time prekey (optional)
PQ  = KEM.Encaps(PQ_PK_B)      — ML-KEM-1024 encapsulation

SK = HKDF(DH1 || DH2 || DH3 || DH4 || PQ_SS, "TR3_SESSION_v1")
```

**Critical:** Ed25519 keys are for signing/identity. X25519 keys are for DH. They are separate key pairs. Mixing them up breaks everything (we learned this the hard way).

### Sealed Sender

Ephemeral ECDH envelope hides sender identity from server:
- Sender does ECDH with recipient's X25519 identity DH key
- Derives envelope key, encrypts sender certificate + inner payload
- Server sees only recipient device ID + opaque blob

### Key Types

All defined in `shared/src/types.rs`:

| Type | Size | Purpose |
|------|------|---------|
| `IdentityPublicKey` | 32B | Ed25519 public (signing/identity) |
| `PublicKey` | 32B | X25519 public (DH operations) |
| `PrivateKey` | 32B | X25519 private |
| `PqPublicKey` | 1568B | ML-KEM-1024 public |
| `PqSecretKey` | 3168B | ML-KEM-1024 secret |
| `RootKey` | 32B | Root of ratchet chain |
| `ChainKey` | 32B | Symmetric ratchet chain state |
| `MessageKey` | 32B | Per-message AES-GCM key |
| `HeaderKey` | 32B | Header encryption key |

---

## Server

### Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/v1/register` | None | Create account (phone hash) |
| POST | `/v1/verify` | None | POC no-op |
| POST | `/v1/keys/upload` | None | Upload device + prekey bundle |
| GET | `/v1/keys/{device_id}` | X-Device-ID | Fetch prekey bundle (pops one-time prekey) |
| POST | `/v1/messages/send` | **None** (sealed sender) | Queue opaque envelope |
| GET | `/v1/messages/receive` | X-Device-ID | Poll message queue |
| POST | `/v1/messages/ack` | X-Device-ID | Delete processed messages |
| GET | `/v1/ws` | — | WebSocket (stub) |
| GET | `/health` | None | Health check |

**Auth model:** POC uses `X-Device-ID` header (trusted). Send endpoint has NO auth — sealed sender means server doesn't know who sent the message. Production should use signed JWTs.

### Database

PostgreSQL with zero-knowledge design. Server stores:
- Phone hashes (SHA256, not plaintext)
- Public keys only (identity, signed prekey, PQ prekey, one-time prekeys)
- Opaque encrypted envelopes (cannot read content)
- Key transparency log (append-only audit trail)

Schema: `server/migrations/001_initial.sql`

One-time prekey pop uses `FOR UPDATE SKIP LOCKED` for concurrent safety.

### Environment Variables

```
DATABASE_URL=postgres://echo:echo@localhost/echo
REDIS_URL=redis://127.0.0.1:6379
SMS_API_KEY=poc-key
PORT=8080
```

---

## CLI Client

Binary: `echo`

### Commands

```bash
# Register identity and upload prekeys
echo -i alice register --phone "+15551234567"

# Show identity info
echo -i alice whoami

# Fetch prekeys and establish session (X4DH)
echo -i alice session --device <bob-device-uuid>

# Send encrypted message (sealed sender)
echo -i alice send --to <bob-device-uuid> -m "hello"

# Poll and decrypt incoming messages
echo -i bob recv
```

### Wire Message Format

First message is a `PreKey` message (includes X4DH init data so recipient can establish session). Subsequent messages are `Normal` (smaller).

```
PreKey:  ~2322 bytes (sealed) — includes ephemeral key, PQ ciphertext, identity keys
Normal:  ~621 bytes (sealed) — just ratchet header + ciphertext
```

### Local Storage

Identity and sessions stored as JSON in `~/.echo/<identity>/`:
```
~/.echo/alice/
  identity.json          — Ed25519 + X25519 + signed prekey + PQ keys + OTP private keys
  sessions/
    <device-uuid>.ratchet.json   — Full ratchet state (root key, chains, counters)
    <device-uuid>.meta.json      — Session metadata (recipient DH key, ephemeral, etc.)
```

**Note:** Secret keys are stored in plaintext JSON for POC. Production must use encrypted storage (SQLCipher or OS keychain).

---

## Test Results

### Integration Tests (12/12 passing)

```
test_x4dh_session_establishment
test_x4dh_without_one_time_prekey
test_x4dh_bad_signature_rejected
test_triple_ratchet_single_message
test_triple_ratchet_multiple_messages_one_direction
test_triple_ratchet_bidirectional
test_sealed_sender_roundtrip
test_sealed_sender_wrong_recipient_fails
test_full_flow_x4dh_ratchet_sealed_sender
test_replay_protection
test_pq_kem_roundtrip
test_padding_constant_size
```

Run: `cargo test --package echo-crypto --test integration`

### End-to-End (verified manually)

```
alice register  -> account + device + 100 OTPs uploaded
bob register    -> account + device + 100 OTPs uploaded
alice session   -> X4DH + PQ KEM + one-time prekey consumed
alice send      -> TR3 encrypt -> sealed sender -> server queue (prekey msg)
bob recv        -> poll -> unseal -> X4DH respond -> decrypt OK
bob send        -> ratchet forward -> seal -> queue
alice recv      -> unseal -> decrypt OK
alice send x2   -> normal messages (ratchet advancing)
bob recv        -> both decrypted OK
```

---

## Bugs Fixed During Development

These are worth knowing so they don't get re-introduced:

1. **Ed25519/X25519 key confusion** — Identity keys are Ed25519 (signing). DH operations need X25519. `PrekeyBundle` has both `identity_key` (Ed25519) and `identity_dh_key` (X25519). Using the wrong one for DH silently produces mismatched shared secrets.

2. **Responder has no sending chain** — After X4DH, the responder only gets a receiving chain. First encrypt auto-triggers `dh_ratchet_send()` when `sending_chain_key.is_none()`.

3. **Replay detection used wrong identifier** — `prev_chain_length` is not unique across DH ratchet steps. Fixed by adding `dh_ratchet_number` to `MessageHeader` and using `(epoch, dh_ratchet_number, msg_number)` tuple.

4. **`#[serde(skip)]` on secret fields** — Chain keys, header keys, and DH private keys were marked `serde(skip)` for security. This broke persistence — state loaded from disk had None for all secrets. Removed for POC. Production must use encrypted storage instead.

5. **Sealed sender key mismatch** — `save_session` was using Ed25519 identity bytes as the sealed sender recipient key. Must use X25519 `identity_dh_key` from the prekey bundle.

6. **One-time prekey private keys not saved** — OTP private keys weren't persisted to disk, so Bob couldn't complete DH4 in X4DH::respond. Added `one_time_prekeys` to `IdentityState`.

7. **Responder `peer_dh_public` not set** — Bob's responder state needs `peer_dh_public = Some(alice_dh_public)` from the message header, otherwise the decrypt triggers a spurious DH ratchet step that desynchronizes the chains.

---

## What's Next

### Must-Have for Production

- [ ] **Encrypted local storage** — Replace JSON files with SQLCipher or OS keychain. The `serde(skip)` attributes were removed for POC; secrets are in plaintext on disk.
- [ ] **JWT auth** — Replace `X-Device-ID` header trust with signed tokens.
- [ ] **PreKey message handling on server** — Server should distinguish prekey messages from normal messages (or let client handle it, which is current approach).
- [ ] **One-time prekey replenishment** — Client should auto-upload more OTPs when the server runs low.
- [ ] **WebSocket real-time delivery** — Currently polling only. WS handler is stubbed.
- [ ] **Certificate validation** — `SenderCertificate.server_signature` is a placeholder (64 zero bytes). Server should sign sender certs.
- [ ] **Key rotation** — Signed prekey and PQ prekey rotation on schedule.
- [ ] **Message delivery receipts** — Read receipts, delivery confirmations.

### Nice-to-Have

- [x] **Flutter client** — Implemented (see Flutter Client section below). Needs FFI codegen + Flutter SDK to build.
- [ ] **Group messaging** — `shared/src/group/mod.rs` has the Sender Key protocol scaffolded.
- [ ] **Key transparency** — Log table exists, Merkle root column is there, background process needed.
- [ ] **Rate limiting** — Redis is connected, middleware returns Identity (passthrough). Needs actual rate limit logic.
- [ ] **Disappearing messages** — Message queue has `expires_at` column (30 day default).
- [ ] **Multi-device** — Schema supports multiple devices per account, but session management is single-device.

---

## Flutter Client

### Overview

Full Flutter/Dart client at `client/` targeting Android. Uses flutter_rust_bridge v2 for FFI into the Rust crypto library, Riverpod for state management, sqflite for local DB, flutter_secure_storage for private keys, and dio for HTTP.

### Architecture

```
client/lib/
├── main.dart                          — App entry point (ProviderScope + MaterialApp.router)
├── router/app_router.dart             — go_router with auth guard (redirects to onboarding if no identity)
├── ffi/                               — Generated by flutter_rust_bridge (not yet run)
├── data/
│   ├── local/
│   │   ├── database.dart              — sqflite: identity, sessions, messages, contacts tables
│   │   └── secure_storage.dart        — flutter_secure_storage: ed/dh/spk/pq private keys, OTP map
│   ├── models/
│   │   ├── identity.dart              — account_id, device_id, ed/dh public keys
│   │   ├── session.dart               — peer_device_id, ratchet_state JSON, session meta
│   │   ├── message.dart               — conversation_id, content, status, timestamp
│   │   └── contact.dart               — device_id, display_name, fingerprint
│   └── repositories/
│       ├── identity_repository.dart   — CRUD for identity (singleton row)
│       ├── session_repository.dart    — Per-peer ratchet state persistence
│       ├── message_repository.dart    — Messages + ConversationSummary queries
│       └── contact_repository.dart    — Known peer devices
├── services/
│   ├── api_service.dart               — dio HTTP client mirroring server REST API
│   ├── crypto_service.dart            — Dart interface to Rust FFI (methods defined, bodies need codegen)
│   ├── session_service.dart           — X4DH session establishment (initiator + responder)
│   ├── message_service.dart           — E2E send/receive: encrypt→wire→seal→HTTP→state→store
│   ├── polling_service.dart           — Timer.periodic 3s, lifecycle-aware pause/resume
│   └── registration_service.dart      — Keygen→register→upload prekeys→save identity
├── providers/
│   ├── service_providers.dart         — Riverpod providers for all repos + services
│   ├── identity_provider.dart         — AsyncNotifier: current user identity
│   ├── conversations_provider.dart    — AsyncNotifier: conversation list from DB
│   ├── messages_provider.dart         — FamilyAsyncNotifier: messages per conversation
│   └── connection_provider.dart       — Notifier: polling status
└── screens/
    ├── onboarding/
    │   ├── welcome_screen.dart        — Landing page with lock icon + Get Started
    │   ├── phone_input_screen.dart    — Phone number entry
    │   └── registration_screen.dart   — Keygen progress + auto-register
    ├── home/
    │   ├── home_screen.dart           — Conversation list, pull-to-refresh, connection indicator
    │   └── conversation_tile.dart     — Last message preview, timestamp
    ├── chat/
    │   ├── chat_screen.dart           — Message list + input + safety number dialog
    │   ├── chat_input.dart            — TextField with send button
    │   └── message_bubble.dart        — Outgoing/incoming bubbles with status icons
    ├── new_chat/
    │   └── new_chat_screen.dart       — UUID input, session establishment, X4DH info card
    └── settings/
        ├── settings_screen.dart       — Device ID, account, protocol info
        └── identity_screen.dart       — Ed25519/X25519 public keys, fingerprint display
```

### Rust FFI Bridge

`shared/src/ffi_api.rs` — 16 stateless functions designed for flutter_rust_bridge v2 codegen:

| Function | Purpose |
|----------|---------|
| `ffi_generate_identity()` | Generate Ed25519 + X25519 + SPK + PQ keys |
| `ffi_generate_one_time_prekeys()` | Batch generate OTP X25519 keys |
| `ffi_x4dh_initiate()` | Alice's X4DH (4 DH + PQ KEM) |
| `ffi_x4dh_respond()` | Bob's X4DH response |
| `ffi_ratchet_encrypt()` | Encrypt with triple ratchet, return updated state JSON |
| `ffi_ratchet_decrypt()` | Decrypt, return updated state JSON + plaintext |
| `ffi_seal_message()` | Sealed sender envelope |
| `ffi_unseal_message()` | Unseal envelope |
| `ffi_build_initiator_state()` | Build initiator RatchetState from X4DH result |
| `ffi_build_responder_state()` | Build responder RatchetState from X4DH response |
| `ffi_build_prekey_wire_message()` | Serialize PreKey wire message (bincode) |
| `ffi_build_normal_wire_message()` | Serialize Normal wire message (bincode) |
| `ffi_parse_wire_message()` | Deserialize wire message from bytes |
| `ffi_sha256()` | SHA-256 hash utility |

**Key design:** RatchetState crosses the FFI boundary as JSON strings (already has serde derives). No mutable Rust objects held across FFI calls. Each call takes state in, returns updated state out.

### Message Flow (send)

```
sendMessage(recipientDeviceId, text)
  │
  ├─ SessionRepository.load(peerDeviceId)     → ratchet_state JSON
  ├─ CryptoService.ratchetEncrypt(state, text) → (new_state, header, enc_header, ciphertext)
  ├─ CryptoService.buildWireMessage(...)       → wire_payload bytes
  ├─ CryptoService.sealMessage(...)            → sealed envelope bytes
  ├─ ApiService.sendMessage(recipient, hex)    → HTTP POST
  ├─ SessionRepository.updateRatchetState()    → persist new state
  └─ MessageRepository.insert()               → store locally
```

### Message Flow (receive/poll)

```
pollMessages()
  │
  ├─ ApiService.receiveMessages()              → [QueuedMessageDto]
  ├─ For each message:
  │   ├─ CryptoService.unsealMessage()         → (sender_cert, tr3_ciphertext)
  │   ├─ CryptoService.parseWireMessage()      → wire components
  │   ├─ If PreKey + no session:
  │   │   └─ SessionService.handlePreKeyMessage() → X4DH respond + create session
  │   ├─ CryptoService.ratchetDecrypt()        → (new_state, plaintext)
  │   ├─ SessionRepository.updateRatchetState()
  │   └─ MessageRepository.insert()
  └─ ApiService.ackMessages(ids)
```

### Dependencies (pubspec.yaml)

```yaml
flutter_rust_bridge: ^2.0.0    # FFI codegen from Rust
flutter_riverpod: ^2.4.0       # State management
go_router: ^13.0.0             # Navigation with auth guard
dio: ^5.4.0                    # HTTP client
sqflite: ^2.3.0                # Local SQLite database
flutter_secure_storage: ^9.0.0 # OS keychain for private keys
uuid: ^4.2.0                   # UUID generation
convert: ^3.1.0                # Hex encoding
```

### What's Left to Make It Run

1. **Install Flutter SDK** and run `flutter create .` inside `client/` to generate platform scaffolding (AndroidManifest, Gradle, etc.)
2. **Run flutter_rust_bridge codegen:** `flutter_rust_bridge_codegen generate` pointing at `shared/src/ffi_api.rs`
3. **Replace `throw UnimplementedError`** in `CryptoService` methods with actual generated FFI calls (they currently define the interface but need the codegen output)
4. **Test pqcrypto-kyber cross-compilation** — ML-KEM-1024 uses PQClean C code. Android NDK may need explicit `CC`/`AR` in `.cargo/config.toml`. If it fails, fall back to vendoring PQClean with CMake.
5. **Wire up identity context** — `SessionService` and `MessageService` have placeholder bytes for our own identity/device ID in wire messages. These need to be injected from the identity provider at call sites.

### Risk: pqcrypto-kyber cross-compilation

ML-KEM-1024 uses PQClean C code. Android NDK provides the C toolchain but may need explicit `CC`/`AR` in `.cargo/config.toml`. Test this before writing more Dart code. If it fails, fall back to vendoring PQClean with CMake or using a pure-Rust PQ implementation.

---

## How to Run

### Prerequisites

```bash
# PostgreSQL and Redis running
sudo systemctl start postgresql redis-server

# Create database
sudo -u postgres psql -c "CREATE USER echo WITH PASSWORD 'echo';"
sudo -u postgres psql -c "CREATE DATABASE echo OWNER echo;"

# Run migration
PGPASSWORD=echo psql -h localhost -U echo -d echo -f server/migrations/001_initial.sql
```

### Start Server

```bash
DATABASE_URL="postgres://echo:echo@localhost/echo" \
REDIS_URL="redis://127.0.0.1:6379" \
SMS_API_KEY="poc-key" \
cargo run --package echo-server
```

### Run Full Flow

```bash
# Terminal 1: Register Alice
cargo run --package echo-cli -- -i alice register --phone "+15551234567"
# Note Alice's device ID

# Terminal 2: Register Bob
cargo run --package echo-cli -- -i bob register --phone "+15559876543"
# Note Bob's device ID

# Alice establishes session with Bob
cargo run --package echo-cli -- -i alice session --device <bob-device-id>

# Alice sends
cargo run --package echo-cli -- -i alice send --to <bob-device-id> -m "hello"

# Bob receives
cargo run --package echo-cli -- -i bob recv

# Bob replies
cargo run --package echo-cli -- -i bob send --to <alice-device-id> -m "hey back"

# Alice receives
cargo run --package echo-cli -- -i alice recv
```

### Run Tests

```bash
cargo test --package echo-crypto --test integration
```
