-- ECHO Messenger: Initial Schema
-- Zero-knowledge design: server stores only encrypted blobs and hashes

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE accounts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    phone_hash BYTEA NOT NULL UNIQUE,  -- SHA256(phone || server_salt)
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT phone_hash_size CHECK (length(phone_hash) = 32)
);

CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    identity_key BYTEA NOT NULL,            -- Ed25519 public (32 bytes)
    identity_dh_key BYTEA NOT NULL,         -- X25519 public (32 bytes) for DH operations
    signed_prekey BYTEA NOT NULL,           -- X25519 public (32 bytes)
    signed_prekey_sig BYTEA NOT NULL,       -- Ed25519 signature (64 bytes)
    signed_prekey_id INTEGER NOT NULL,
    pq_prekey BYTEA,                        -- ML-KEM-1024 public key (1568 bytes)
    pq_prekey_sig BYTEA,                    -- Ed25519 signature of PQ prekey
    pq_prekey_id INTEGER,
    push_token_encrypted BYTEA,             -- Client-encrypted, server CANNOT read
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(account_id, identity_key)
);

CREATE TABLE onetime_prekeys (
    id BIGSERIAL PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key_id INTEGER NOT NULL,
    public_key BYTEA NOT NULL,              -- X25519 (32 bytes)
    pq_public_key BYTEA,                    -- ML-KEM-1024 (1568 bytes) optional
    uploaded_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(device_id, key_id)
);
CREATE INDEX idx_onetime_device ON onetime_prekeys(device_id);

CREATE TABLE message_queue (
    id BIGSERIAL PRIMARY KEY,
    recipient_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    envelope BYTEA NOT NULL,                -- Sealed sender blob (server CANNOT read)
    queued_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ DEFAULT NOW() + INTERVAL '30 days'
);
CREATE INDEX idx_queue_recipient ON message_queue(recipient_device_id, queued_at);

CREATE TABLE groups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    encrypted_metadata BYTEA NOT NULL,      -- Name, avatar encrypted by group key
    epoch INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE group_members (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    role SMALLINT DEFAULT 0,                -- 0=member, 1=admin
    joined_epoch INTEGER NOT NULL,
    PRIMARY KEY (group_id, device_id)
);

-- Key transparency log (append-only for auditing)
CREATE TABLE key_transparency_log (
    sequence_id BIGSERIAL PRIMARY KEY,
    device_id UUID NOT NULL,
    identity_key_hash BYTEA NOT NULL,       -- SHA256 of identity key
    logged_at TIMESTAMPTZ DEFAULT NOW(),
    merkle_root BYTEA                       -- Updated by background process
);
CREATE INDEX idx_ktl_device ON key_transparency_log(device_id);

-- Verification codes (ephemeral)
CREATE TABLE verification_codes (
    phone_hash BYTEA PRIMARY KEY,
    code_hash BYTEA NOT NULL,               -- SHA256(code || salt)
    salt BYTEA NOT NULL,
    attempts INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ DEFAULT NOW() + INTERVAL '10 minutes'
);
