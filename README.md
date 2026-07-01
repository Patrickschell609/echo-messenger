# ECHO

**Post-quantum encrypted messenger. Zero-knowledge server. No phone number. No metadata. No backdoors.**

## The Problem

In 2025, classified military strike plans were shared in a group chat on the world's most trusted encrypted messenger. The wrong person was in the chat. The plans leaked. An inspector general investigation confirmed the messages contained information marked SECRET/NOFORN.

The app worked exactly as designed. The encryption held. The protocol was fine.

It didn't matter.

The same year, a journalist claimed intelligence agencies had been reading his private messages on the same platform -- not by breaking the encryption, but by exploiting everything around it: metadata, phone numbers, linked devices, cloud infrastructure subject to legal demands.

A Pentagon-wide advisory followed, warning that foreign hacking groups were exploiting the "linked devices" feature to spy on encrypted conversations. The app that was supposed to protect sensitive communications had become a liability.

This isn't a flaw in one product. It's a flaw in the model.

## Why Encrypted Messengers Fail

They fail because encryption is only one layer, and most messengers protect that layer while leaving everything else exposed:

**Phone numbers are identity.** Every major encrypted messenger requires a phone number to register. That phone number is a permanent, government-issued identifier tied to your real name, your billing address, your location history. Encryption means nothing when your identity is stapled to every message you send.

**Metadata is surveillance.** Who you talk to, when, how often, for how long. End-to-end encryption protects content. It does nothing for metadata. And metadata is often more valuable than content -- intelligence agencies have said publicly that they "kill people based on metadata."

**App stores are chokepoints.** If your messenger is distributed through Google Play or the Apple App Store, those companies can pull it, push silent updates, or comply with government orders to modify it. The app store is a single point of compromise for every user simultaneously.

**Classical crypto has an expiration date.** Nation-state actors are running harvest-now-decrypt-later operations right now, stockpiling encrypted traffic to break when quantum computers mature. The leading encrypted messenger acknowledged in its own documentation that its authentication mechanism "is not quantum-secure" and that "in the presence of an active quantum adversary, the parties receive no cryptographic guarantees as to who they are communicating with."

## What ECHO Does Differently

ECHO was built from scratch to close every gap, not just the encryption gap.

### No Phone Number. No Email. No Identity.

You register with an invite code. That's it. No phone number, no email, no OAuth, no app store account. Your identity is a cryptographic keypair generated on your device. The server never knows who you are. There is nothing to subpoena.

### Triple Ratchet Protocol

Three layers of forward secrecy -- not one:

| Layer | Mechanism | Ratchets | Purpose |
|-------|-----------|----------|---------|
| Symmetric | HKDF-SHA256 chain | Every message | Forward secrecy per message |
| DH | X25519 Diffie-Hellman | Every turn | Break-in recovery |
| Post-Quantum | Kyber-1024 KEM | Every 100 messages or 24h | Quantum resistance |

Every major messenger uses a double ratchet. ECHO adds a third layer: periodic Kyber-1024 (NIST PQC round-3 selection; FIPS 203 ML-KEM migration planned) key encapsulation that makes harvested ciphertext permanently worthless to quantum computers. This isn't bolted on -- it's woven into the ratchet. After every PQ epoch, a DH ratchet is forced so quantum protection propagates to all subsequent chain keys immediately.

### X4DH Key Agreement

Session establishment extends the X3DH protocol with a post-quantum KEM:

1. Identity key exchange (Ed25519 + X25519)
2. Signed prekey exchange (X25519)
3. One-time prekey exchange (X25519)
4. Ephemeral key exchange (X25519)
5. Kyber-1024 encapsulation

The result: a shared secret derived from 4 DH operations plus a post-quantum KEM. Both parties' Ed25519 identity keys are bound into the session KDF, preventing unknown key-share attacks. Authentication is cryptographic end-to-end -- not dependent on classical assumptions that quantum computers will break.

### Sealed Sender

The server never learns who sent a message. Each message is wrapped in an ephemeral ECDH envelope using the recipient's public key. The server sees an opaque blob addressed to a device ID. It cannot read it, cannot identify the sender, cannot correlate traffic patterns to real identities. Sender certificates require dual signatures (server + sender Ed25519), preventing the server from forging sender identity even if fully compromised.

### Zero-Knowledge Server (admin=0)

The server is an untrusted relay. By architecture, not by policy.

- Cannot read message content
- Cannot identify message senders
- Cannot substitute keys undetected (Merkle-based key transparency)
- Cannot forge user identities (Ed25519 counter-signed certificates)
- Cannot decrypt stored messages even if physically seized
- Has no admin panel, no master key, no god mode
- Has no compliance interface because there is nothing to comply with

If someone takes the server, they get encrypted blobs they can never open, addressed to UUIDs they can never resolve to humans. That's it.

### No App Store

ECHO is not distributed through any app store. There is no update mechanism controlled by a third party. There is no kill switch. You build from source or you get the binary from someone you trust. This is a feature, not a limitation.

## Security Audit

22 vulnerabilities were identified and fixed in a comprehensive security review:

- **4 Critical**: Sender cert forgery, transparency timestamp manipulation, identity key binding, X4DH verification bypass
- **6 High**: Sealed sender bypass, vault authentication, memory zeroization, replay attacks, IP spoofing, group metadata leakage
- **12 Medium**: Ratchet chain gaps, key material zeroization, KDF identity binding, WebSocket replay, message TTL, header encryption

All 67 cryptographic tests pass. Every DH shared secret, PQ shared secret, and ratchet state is explicitly zeroized after use to prevent memory forensics.

## Features

- 1:1 end-to-end encrypted chat with post-quantum protection
- Group messaging (sender key distribution over pairwise channels)
- File and image transfer (encrypted in the ratchet payload)
- Typing indicators, delivery receipts, read receipts
- Auto-delete timer (per-conversation, synced between peers)
- Edit and delete sent messages (via encrypted control messages)
- Message search (client-side only, encrypted at rest)
- Short-code friend exchange (8 characters, no ambiguous letters)
- Invite-only network (no open registration, no bots, no spam)
- Encrypted local vault (Argon2id + AES-256-GCM)

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
3. Session establishes automatically. Green dot = connected and encrypted.

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

Point a reverse proxy (Caddy, nginx) at port 8090 with TLS. Tell clients to use your domain as the server URL. You now run a zero-knowledge message relay that you cannot spy on even if you wanted to.

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
| Post-quantum KEM | Kyber-1024 (NIST PQC round 3; FIPS 203 ML-KEM migration planned) |
| Symmetric encryption | AES-256-GCM |
| Key derivation | HKDF-SHA256 |
| Password hashing | Argon2id (64MB/3 iterations) |
| Hash function | SHA-256 |
| Signatures | Ed25519 (RFC 8032) |

## License

AGPL-3.0. If you run a modified server, you must publish your source. The encryption belongs to everyone.

---

Built by [Ghost](https://github.com/Patrickschell609) and Claude.
