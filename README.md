# ECHO

Post-quantum encrypted messenger. No phone number. No metadata. Admin keys burned.

X4DH key agreement + Triple Ratchet (X25519 + ML-KEM-1024) + sealed sender. The server is zero-knowledge: it routes opaque blobs and can't read your messages. Invite-only. Desktop only. By design.

## Install (Linux)

Download the `.deb` from [Releases](https://github.com/Patrickschell609/echo-messenger/releases):

```
sudo dpkg -i ECHO_0.1.0_amd64.deb
```

Launch ECHO from your application menu or run `echo-app` from terminal.

## Create an Account

1. Enter the server URL: `echo.biotwin.io`
2. Choose a passphrase (12+ characters). This encrypts your keys locally. There is no recovery. Lose it and your identity is gone.
3. Enter an invite code. You need one from someone already on the network.

## Add a Friend

Your friend gives you their device ID (shown on their profile screen). Paste it into the buddy list. A session establishes automatically. When the heartbeat turns green, you're live.

## Run Your Own Server

Requirements: PostgreSQL 15+, Redis, Linux.

```bash
# Create database
sudo -u postgres createuser echo_user --pwprompt
sudo -u postgres createdb echo --owner=echo_user

# Configure
cp deploy/.env.example /opt/echo/.env
# Edit /opt/echo/.env with your credentials

# Install
sudo useradd --system --no-create-home echo
sudo mkdir -p /opt/echo
sudo cp target/release/echo-server /opt/echo/
sudo cp deploy/echo-server.service /etc/systemd/system/
sudo systemctl enable --now echo-server

# Check logs for genesis invite code
sudo journalctl -u echo-server | grep GENESIS
```

Migrations run automatically on startup. Point a reverse proxy (Caddy, nginx) at port 8090. Tell your clients to use your domain as the server URL.

## Architecture

Three ratchet layers protect every message:

| Layer | Mechanism | Ratchets |
|-------|-----------|----------|
| Symmetric | HKDF-SHA256 chain | Every message |
| DH | X25519 Diffie-Hellman | Every turn |
| Post-Quantum | ML-KEM-1024 KEM | Every 100 messages or 24 hours |

Session establishment uses X4DH (4 DH operations + post-quantum KEM). Sealed sender hides who sent each message from the server. Key transparency provides an append-only audit log of all public keys.

The server stores only public keys and opaque encrypted envelopes. No plaintext. No message content. No sender identity on the wire.

## What's in v0.1.0

- 1:1 encrypted chat
- Group messaging
- Typing indicators, delivery receipts, read receipts
- File and image transfer
- Auto-delete timer
- Edit and delete sent messages
- QR safety number verification
- Invite code system

## No Mobile

Desktop only. No iOS. No Android. The Flutter client is dead code from the POC phase. Long-term native integration is through XP Reborn, not app stores.

## Build from Source

```bash
# Server
cargo build --release -p echo-server

# Desktop client (requires Tauri CLI)
cd echo-app && cargo tauri build

# Tests
cargo test --workspace
```

## License

AGPL-3.0
