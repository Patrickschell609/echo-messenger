# ECHO

**Post-quantum encrypted messenger. Zero-knowledge server. No phone number. No metadata. No backdoors.**

ECHO is a from-scratch encrypted messenger built for the post-quantum era. Every message is protected by a triple ratchet protocol combining classical X25519 with ML-KEM-1024 (NIST FIPS 203), so your conversations are secure against both today's adversaries and tomorrow's quantum computers.

The server is a dumb pipe. It routes opaque encrypted blobs and cannot read, decrypt, or comply with requests for message content. There are no admin keys. There is no master decryption key. There is no backdoor. By design, not by policy.

> *"First Ever Post Quantum Message sent at 2:07 pm feb 25 by Ghost"*

## Why This Matters

Every message sent over classical encryption today is being collected. Nation-state actors are running harvest-now-decrypt-later operations, stockpiling encrypted traffic to break when quantum computers mature. Signal, WhatsApp, iMessage all rely on classical key exchange that quantum computers will shatter.

ECHO was built to make that stockpile worthless.

## How It Works

### Triple Ratchet Protocol

Three ratchet layers protect every message:

| Layer | Mechanism | Ratchets | Purpose |
|-------|-----------|----------|---------|
| Symmetric | HKDF-SHA256 chain | Every message | Forward secrecy per message |
| DH | X25519 Diffie-Hellman | Every turn | Break-in recovery |
| Post-Quantum | ML-KEM-1024 KEM | Every 100 messages or 24h | Quantum resistance |

### X4DH Key Agreement

Session establishment extends the Signal X3DH protocol with a post-quantum KEM:

1. Identity key exchange (Ed25519 + X25519)
2. Signed prekey exchange (X25519)
3. One-time prekey exchange (X25519)
4. Ephemeral key exchange (X25519)
5. ML-KEM-1024 encapsulation

The result is a shared secret derived from 4 DH operations plus a post-quantum KEM. Both parties' Ed25519 identity keys are bound into the session KDF, preventing unknown key-share attacks.

### Sealed Sender

The server never learns who sent a message. Each message is wrapped in an ephemeral ECDH envelope (sender's ephemeral key + recipient's identity key) so the server sees only the recipient's device ID and an opaque ciphertext blob.

### Key Transparency

An append-only Merkle log records every public key upload. Clients verify inclusion and consistency proofs to detect key substitution attacks. The server cannot silently swap a user's public keys without detection.

### Zero-Knowledge Server (admin=0)

The server:
- Cannot read message content (sealed sender + end-to-end encryption)
- Cannot identify message senders (sealed sender)
- Cannot substitute keys undetected (key transparency)
- Cannot forge user identities (Ed25519 signatures, counter-signed certificates)
- Cannot decrypt stored messages even if fully compromised
- Has no admin panel, no master key, no god mode

## Security Audit

22 vulnerabilities were identified and fixed in a comprehensive security review:

- **4 Critical**: Sender cert forgery, transparency timestamp manipulation, identity key binding, X4DH verification bypass
- **6 High**: Sealed sender bypass, vault authentication, memory zeroization, replay attacks, IP spoofing, group metadata leakage
- **12 Medium**: Ratchet chain gaps, key material zeroization, KDF identity binding, WebSocket replay, message TTL, header encryption

All 67 cryptographic tests pass. Full details in the commit history.

## Features

- 1:1 end-to-end encrypted chat
- Group messaging
- File and image transfer
- Typing indicators, delivery receipts, read receipts
- Auto-delete timer
- Edit and delete sent messages
- Message search (client-side, encrypted at rest)
- QR code short-code exchange
- Invite-only network (no open registration)
- Encrypted vault (Argon2id + AES-256-GCM local storage)

## Quick Start

### Create an Account

1. Launch ECHO
2. Click "Server settings" and enter: `echo.biotwin.io`
3. Enter a passphrase (12+ characters). This encrypts your keys locally. **There is no recovery.** Lose it and your identity is gone.
4. Enter an invite code from someone already on the network
5. Click "Create Account"

### Add a Friend

1. Share your short code (shown on your profile, format: `A4HD-YCSD`)
2. Click "+ Add Buddy" and enter their short code
3. Click on the buddy to open chat. Session establishes automatically.
4. Green dot = connected and encrypted

## Build from Source

Requirements: Rust 1.75+, PostgreSQL 15+, Redis

```bash
# Clone
git clone https://github.com/Patrickschell609/echo-messenger.git
cd echo-messenger

# Build everything
cargo build --release

# Run tests
cargo test --workspace

# Server binary
./target/release/echo-server

# Desktop client (requires system WebKitGTK on Linux)
./target/release/echo-app
```

## Run Your Own Server

```bash
# Database setup
sudo -u postgres createuser echo_user --pwprompt
sudo -u postgres createdb echo --owner=echo_user

# Configure environment
cp deploy/.env.example .env
# Edit .env with your DATABASE_URL and REDIS_URL

# Run (migrations are automatic)
cargo run --release -p echo-server

# Check logs for the genesis invite code
grep GENESIS /tmp/echo-server.log
```

Point a reverse proxy (Caddy, nginx) at port 8090 with TLS. Tell clients to use your domain as the server URL. That's it. You now run a zero-knowledge message relay.

## Architecture

```
echo-messenger/
  shared/          # Crypto core: triple ratchet, X4DH, sealed sender, KDF, AEAD
  echo-client/     # Client library: HTTP, WebSocket, vault, identity, wire format
  echo-app/        # Tauri v2 desktop app (Rust backend + vanilla JS frontend)
  server/          # Axum server: REST API, WebSocket, PostgreSQL, Redis
  cli/             # CLI client and E2E tests
```

All cryptography lives in `shared/` with 67 unit and integration tests. The server never imports crypto primitives because it never touches plaintext.

## Cryptographic Primitives

| Purpose | Primitive |
|---------|-----------|
| Identity keys | Ed25519 |
| Key agreement | X25519 |
| Post-quantum KEM | ML-KEM-1024 (FIPS 203) |
| Symmetric encryption | AES-256-GCM |
| Key derivation | HKDF-SHA256 |
| Password hashing | Argon2id |
| Hash function | SHA-256 |
| Signatures | Ed25519 (RFC 8032) |

## No Mobile (Yet)

Desktop only. Linux confirmed. macOS and Windows should work via Tauri but are untested. Mobile is not a priority. The protocol is the product.

## License

AGPL-3.0. If you run a modified server, you must publish your source. The encryption belongs to everyone.

---

Built by [Ghost](https://github.com/Patrickschell609) and Claude. First bilateral post-quantum encrypted message: February 25, 2026.
