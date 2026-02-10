-- Invite code system: replaces phone-based registration
CREATE TABLE invite_codes (
    id BIGSERIAL PRIMARY KEY,
    code_hash BYTEA NOT NULL UNIQUE,
    creator_device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    redeemed_by UUID REFERENCES accounts(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ DEFAULT NOW() + INTERVAL '7 days',
    is_genesis BOOLEAN DEFAULT FALSE,
    CONSTRAINT code_hash_size CHECK (length(code_hash) = 32)
);

CREATE INDEX idx_invite_code_hash ON invite_codes(code_hash);

-- Phone hash is no longer required for invite-based registration
ALTER TABLE accounts ALTER COLUMN phone_hash DROP NOT NULL;
ALTER TABLE accounts DROP CONSTRAINT IF EXISTS accounts_phone_hash_key;
CREATE UNIQUE INDEX IF NOT EXISTS accounts_phone_hash_unique
    ON accounts(phone_hash) WHERE phone_hash IS NOT NULL;

-- Track who invited whom
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS invited_by UUID REFERENCES accounts(id);
