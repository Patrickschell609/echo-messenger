//! Transparency log signing key management.
//!
//! Loads or generates an Ed25519 keypair used to sign tree heads.
//!
//! If `TRANSPARENCY_KEY_PASSWORD` is set, the key file is encrypted:
//!   salt(32) || nonce(12) || ciphertext(32 + 16 GCM tag)
//! Otherwise, the key is stored as a plaintext 32-byte file (dev mode warning).

use std::path::PathBuf;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use ed25519_dalek::SigningKey;
use rand::{rngs::OsRng, RngCore};

/// Holds the Ed25519 keypair for signing Signed Tree Heads.
#[derive(Clone)]
pub struct TransparencySigningKey {
    signing: SigningKey,
    pub public_key: [u8; 32],
    /// Paired ML-DSA-87 key (post-quantum half), derived from the Ed25519 seed.
    ml_dsa_secret: Vec<u8>,
    pub ml_dsa_public: Vec<u8>,
}

/// Argon2id parameters for key encryption.
const ARGON2_M_COST: u32 = 65536; // 64 MB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;

impl TransparencySigningKey {
    /// Load from file or generate new.
    /// If TRANSPARENCY_KEY_PASSWORD is set, the key is encrypted at rest.
    pub fn load_or_generate() -> anyhow::Result<Self> {
        let path = std::env::var("TRANSPARENCY_KEY_PATH")
            .unwrap_or_else(|_| "./transparency_signing.key".into());
        let path = PathBuf::from(path);
        let password = std::env::var("TRANSPARENCY_KEY_PASSWORD").ok();

        let signing = if path.exists() {
            let bytes = std::fs::read(&path)?;

            if let Some(ref pw) = password {
                // Encrypted format: salt(32) || nonce(12) || ciphertext
                if bytes.len() < 32 + 12 + 16 {
                    return Err(anyhow::anyhow!(
                        "encrypted transparency key file too short ({} bytes)",
                        bytes.len()
                    ));
                }
                let salt = &bytes[..32];
                let nonce_bytes = &bytes[32..44];
                let ciphertext = &bytes[44..];

                let key = derive_encryption_key(pw, salt)?;
                let cipher = Aes256Gcm::new_from_slice(&key)
                    .map_err(|e| anyhow::anyhow!("AES key init: {}", e))?;
                let nonce = Nonce::from_slice(nonce_bytes);

                let plaintext = cipher
                    .decrypt(nonce, ciphertext)
                    .map_err(|_| anyhow::anyhow!("wrong TRANSPARENCY_KEY_PASSWORD or corrupted key file"))?;

                if plaintext.len() != 32 {
                    return Err(anyhow::anyhow!(
                        "decrypted key must be 32 bytes, got {}",
                        plaintext.len()
                    ));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&plaintext);
                SigningKey::from_bytes(&arr)
            } else if bytes.len() == 32 {
                // Plaintext format (dev mode)
                tracing::warn!("transparency key is stored UNENCRYPTED — set TRANSPARENCY_KEY_PASSWORD for production");
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                SigningKey::from_bytes(&arr)
            } else {
                // Might be encrypted but no password provided
                return Err(anyhow::anyhow!(
                    "transparency key file is {} bytes (expected 32 for plaintext). Set TRANSPARENCY_KEY_PASSWORD to decrypt.",
                    bytes.len()
                ));
            }
        } else {
            let signing = SigningKey::generate(&mut OsRng);

            if let Some(ref pw) = password {
                // Write encrypted
                let encrypted = encrypt_key(&signing.to_bytes(), pw)?;
                std::fs::write(&path, encrypted)?;
                tracing::info!(
                    "Generated new ENCRYPTED transparency signing key at {}",
                    path.display()
                );
            } else {
                // Write plaintext (dev mode)
                std::fs::write(&path, signing.to_bytes())?;
                tracing::warn!(
                    "Generated new PLAINTEXT transparency signing key at {} — set TRANSPARENCY_KEY_PASSWORD for production",
                    path.display()
                );
            }

            tracing::info!(
                "PUBLIC KEY (embed in clients): {}",
                hex::encode(signing.verifying_key().to_bytes())
            );
            signing
        };

        let verifying = signing.verifying_key();
        // Derive a paired ML-DSA-87 key deterministically from the Ed25519 seed
        // (domain-separated) so there is no second key file to manage. Stable across
        // restarts, so the published ML-DSA public key never changes.
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"echo-server-mldsa-v1");
        h.update(signing.to_bytes());
        let ml_seed: [u8; 32] = h.finalize().into();
        let (ml_dsa_public, ml_dsa_secret) =
            echo_crypto::crypto::pq_sign::pq_sign_keygen_from_seed(&ml_seed);
        Ok(Self {
            signing,
            public_key: verifying.to_bytes(),
            ml_dsa_secret,
            ml_dsa_public,
        })
    }

    /// Sign data with the transparency key (Ed25519 half).
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let sig = self.signing.sign(data);
        sig.to_bytes().to_vec()
    }

    /// Sign data with the paired ML-DSA-87 key (post-quantum half).
    pub fn sign_ml_dsa(&self, data: &[u8]) -> Vec<u8> {
        echo_crypto::crypto::pq_sign::pq_sign(&self.ml_dsa_secret, data)
            .expect("server ML-DSA signing failed")
    }
}

/// Derive an encryption key from a password + salt using Argon2id.
fn derive_encryption_key(password: &str, salt: &[u8]) -> anyhow::Result<[u8; 32]> {
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
            .map_err(|e| anyhow::anyhow!("argon2 params: {}", e))?,
    );

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("argon2 derivation failed: {}", e))?;

    Ok(key)
}

/// Encrypt a 32-byte key: salt(32) || nonce(12) || ciphertext
fn encrypt_key(key_bytes: &[u8; 32], password: &str) -> anyhow::Result<Vec<u8>> {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    let enc_key = derive_encryption_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&enc_key)
        .map_err(|e| anyhow::anyhow!("AES key init: {}", e))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, key_bytes.as_ref())
        .map_err(|e| anyhow::anyhow!("AES-GCM encrypt: {}", e))?;

    let mut output = Vec::with_capacity(32 + 12 + ciphertext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}
