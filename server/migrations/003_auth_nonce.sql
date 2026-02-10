-- Add one-time auth nonce for key upload authorization.
-- New accounts receive a nonce; key upload consumes it.
ALTER TABLE accounts
    ADD COLUMN auth_nonce BYTEA,
    ADD COLUMN auth_nonce_expires_at TIMESTAMPTZ;
