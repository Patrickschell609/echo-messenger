-- Post-quantum (ML-DSA-87 / FIPS 204) hybrid signature material.
-- Stored alongside the existing Ed25519 columns; both halves are served in the
-- prekey bundle and verified together once clients require them.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS ml_dsa_identity_key BYTEA;        -- ML-DSA-87 identity public key (2592 bytes)
ALTER TABLE devices ADD COLUMN IF NOT EXISTS identity_dh_key_ml_dsa_sig BYTEA; -- ML-DSA-87 signature over the DH-binding message
ALTER TABLE devices ADD COLUMN IF NOT EXISTS signed_prekey_ml_dsa_sig BYTEA;   -- ML-DSA-87 signature over the signed prekey
ALTER TABLE devices ADD COLUMN IF NOT EXISTS pq_prekey_ml_dsa_sig BYTEA;       -- ML-DSA-87 signature over the PQ prekey
