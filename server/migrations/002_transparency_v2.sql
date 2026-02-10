-- ECHO Messenger: Key Transparency V2
-- Extends key_transparency_log with full key data for Merkle leaf construction.

ALTER TABLE key_transparency_log
    ADD COLUMN IF NOT EXISTS identity_key BYTEA,
    ADD COLUMN IF NOT EXISTS identity_dh_key BYTEA,
    ADD COLUMN IF NOT EXISTS signed_prekey BYTEA,
    ADD COLUMN IF NOT EXISTS pq_prekey_hash BYTEA;

CREATE INDEX IF NOT EXISTS idx_ktl_device_seq
    ON key_transparency_log(device_id, sequence_id DESC);
