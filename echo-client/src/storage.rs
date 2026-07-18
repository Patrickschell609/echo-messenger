//! Encrypted vault storage — argon2id + AES-256-GCM.
//!
//! Layout:
//! ~/.echo-app/
//!   config.json         # plaintext: server_url, window pos
//!   vault/
//!     salt.bin          # 32 random bytes
//!     identity.enc      # AES-256-GCM(argon2id(passphrase, salt))
//!     contacts.enc
//!     sessions/<uuid>.ratchet.enc
//!     sessions/<uuid>.meta.enc
//!     history/<uuid>.enc

use std::path::{Path, PathBuf};

use serde::{de::DeserializeOwned, Serialize};
use uuid::Uuid;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use argon2::Argon2;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

/// Argon2id parameters — 64MB memory, 3 iterations, 1 thread.
/// Balanced for security + usability on low-RAM devices.
const ARGON2_M_COST: u32 = 65536; // 64 MB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;

/// Canary magic bytes — encrypted during create(), verified during unlock().
/// Prevents wrong-passphrase acceptance when identity.enc is missing.
const VAULT_CANARY_MAGIC: &[u8; 32] = b"ECHO_VAULT_CANARY_2025_VERIFIED!";

pub struct EncryptedVault {
    base_dir: PathBuf,
    master_key: Option<[u8; 32]>,
}

impl Drop for EncryptedVault {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl EncryptedVault {
    pub fn new(base_dir: &Path) -> Self {
        Self {
            base_dir: base_dir.to_path_buf(),
            master_key: None,
        }
    }

    /// Default app data directory: ~/.echo-app/vault/ (desktop) or data_local_dir/echo-app/vault (mobile).
    pub fn default_path() -> Result<PathBuf> {
        // On mobile (Android/iOS), home_dir may not exist. Prefer data_local_dir.
        if let Some(data_dir) = dirs::data_local_dir() {
            return Ok(data_dir.join("echo-app").join("vault"));
        }
        let home = dirs::home_dir().ok_or_else(|| anyhow!("cannot determine home directory"))?;
        Ok(home.join(".echo-app").join("vault"))
    }

    pub fn is_unlocked(&self) -> bool {
        self.master_key.is_some()
    }

    /// Initialize a new vault with a passphrase. Generates salt and derives master key.
    pub fn create(&mut self, passphrase: &str) -> Result<()> {
        std::fs::create_dir_all(&self.base_dir)?;
        std::fs::create_dir_all(self.base_dir.join("sessions"))?;
        std::fs::create_dir_all(self.base_dir.join("history"))?;
        std::fs::create_dir_all(self.base_dir.join("groups"))?;

        let mut salt = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        std::fs::write(self.base_dir.join("salt.bin"), &salt)?;

        self.master_key = Some(derive_master_key(passphrase, &salt)?);

        // Write canary file — always verified on unlock to catch wrong passphrases
        self.write_file("canary.enc", &VAULT_CANARY_MAGIC.to_vec())?;

        Ok(())
    }

    /// Unlock an existing vault with a passphrase.
    pub fn unlock(&mut self, passphrase: &str) -> Result<()> {
        let salt = std::fs::read(self.base_dir.join("salt.bin"))
            .map_err(|_| anyhow!("vault not initialized — no salt.bin"))?;
        if salt.len() != 32 {
            return Err(anyhow!("corrupt salt.bin"));
        }
        let mut salt_arr = [0u8; 32];
        salt_arr.copy_from_slice(&salt);

        self.master_key = Some(derive_master_key(passphrase, &salt_arr)?);

        // Always verify canary — rejects wrong passphrase even if identity.enc is missing
        let canary_path = self.base_dir.join("canary.enc");
        if canary_path.exists() {
            let canary: Vec<u8> = self.read_file("canary.enc")
                .map_err(|_| anyhow!("wrong passphrase"))?;
            if canary.as_slice() != VAULT_CANARY_MAGIC {
                self.master_key = None;
                return Err(anyhow!("wrong passphrase — canary mismatch"));
            }
        } else {
            // Legacy vault without canary — fall back to identity check, then create canary
            let id_path = self.base_dir.join("identity.enc");
            if id_path.exists() {
                self.read_file::<serde_json::Value>("identity.enc")
                    .map_err(|_| anyhow!("wrong passphrase"))?;
            }
            // Migrate: write canary for future unlocks
            self.write_file("canary.enc", &VAULT_CANARY_MAGIC.to_vec())?;
        }

        Ok(())
    }

    /// Lock the vault — zeroize master key from memory.
    pub fn zeroize(&mut self) {
        if let Some(ref mut key) = self.master_key {
            key.zeroize();
        }
        self.master_key = None;
    }

    /// Write a serializable value encrypted to a file path relative to vault.
    pub fn write_file<T: Serialize>(&self, rel_path: &str, data: &T) -> Result<()> {
        let master = self.master_key.ok_or_else(|| anyhow!("vault locked"))?;
        let json = serde_json::to_vec(data)?;
        let file_key = derive_file_key(&master, rel_path);
        let encrypted = encrypt_data(&file_key, &json)?;

        let full_path = self.base_dir.join(rel_path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(full_path, encrypted)?;
        Ok(())
    }

    /// Read and decrypt a file into a deserializable value.
    pub fn read_file<T: DeserializeOwned>(&self, rel_path: &str) -> Result<T> {
        let master = self.master_key.ok_or_else(|| anyhow!("vault locked"))?;
        let full_path = self.base_dir.join(rel_path);
        let encrypted = std::fs::read(&full_path)
            .map_err(|_| anyhow!("file not found: {}", rel_path))?;
        let file_key = derive_file_key(&master, rel_path);
        let decrypted = decrypt_data(&file_key, &encrypted)?;
        let data: T = serde_json::from_slice(&decrypted)?;
        Ok(data)
    }

    /// Check if a file exists in the vault.
    pub fn file_exists(&self, rel_path: &str) -> bool {
        self.base_dir.join(rel_path).exists()
    }

    /// Delete a file from the vault.
    pub fn delete_file(&self, rel_path: &str) -> Result<()> {
        let full_path = self.base_dir.join(rel_path);
        if full_path.exists() {
            std::fs::remove_file(full_path)?;
        }
        Ok(())
    }

    /// Check if vault has been initialized (salt.bin exists).
    pub fn exists(&self) -> bool {
        self.base_dir.join("salt.bin").exists()
    }

    /// Derive a sub-key for a specific purpose (e.g. "history") from the master key.
    pub fn derive_sub_key(&self, purpose: &str) -> Result<[u8; 32]> {
        let master = self.master_key.ok_or_else(|| anyhow!("vault locked"))?;
        let hk = Hkdf::<Sha256>::new(None, &master);
        let info = format!("echo-vault-subkey:{}", purpose);
        let mut key = [0u8; 32];
        hk.expand(info.as_bytes(), &mut key)
            .map_err(|_| anyhow!("HKDF expand failed"))?;
        Ok(key)
    }

    /// Get the vault base directory path.
    pub fn vault_dir(&self) -> &Path {
        &self.base_dir
    }

    // ─── Session storage (replaces IdentityStore file I/O) ───

    /// Save a session (ratchet state + metadata) for a recipient device.
    pub fn save_session<R: Serialize, M: Serialize>(
        &self,
        recipient_device_id: Uuid,
        ratchet_state: &R,
        meta: &M,
    ) -> Result<()> {
        let ratchet_path = format!("sessions/{}.ratchet.enc", recipient_device_id);
        let meta_path = format!("sessions/{}.meta.enc", recipient_device_id);
        self.write_file(&ratchet_path, ratchet_state)?;
        self.write_file(&meta_path, meta)?;
        Ok(())
    }

    /// Load a session (ratchet state + metadata) for a recipient device.
    pub fn load_session<R: DeserializeOwned, M: DeserializeOwned>(
        &self,
        recipient_device_id: Uuid,
    ) -> Result<(R, M)> {
        let ratchet_path = format!("sessions/{}.ratchet.enc", recipient_device_id);
        let meta_path = format!("sessions/{}.meta.enc", recipient_device_id);
        let ratchet: R = self.read_file(&ratchet_path)?;
        let meta: M = self.read_file(&meta_path)?;
        Ok((ratchet, meta))
    }

    /// Update only the ratchet state for an existing session.
    pub fn update_session<R: Serialize>(
        &self,
        recipient_device_id: Uuid,
        ratchet_state: &R,
    ) -> Result<()> {
        let ratchet_path = format!("sessions/{}.ratchet.enc", recipient_device_id);
        self.write_file(&ratchet_path, ratchet_state)?;
        Ok(())
    }

    /// Check if a session exists for a device.
    pub fn session_exists(&self, recipient_device_id: Uuid) -> bool {
        let ratchet_path = format!("sessions/{}.ratchet.enc", recipient_device_id);
        let meta_path = format!("sessions/{}.meta.enc", recipient_device_id);
        self.file_exists(&ratchet_path) && self.file_exists(&meta_path)
    }

    // ─── Group session storage ───

    /// Save a group session.
    pub fn save_group_session(&self, group_id: &str, session: &echo_crypto::group::GroupSession) -> Result<()> {
        let path = format!("groups/{}.enc", group_id);
        self.write_file(&path, session)
    }

    /// Load a group session.
    pub fn load_group_session(&self, group_id: &str) -> Option<echo_crypto::group::GroupSession> {
        let path = format!("groups/{}.enc", group_id);
        self.read_file(&path).ok()
    }

    /// Delete a group session.
    pub fn delete_group_session(&self, group_id: &str) -> Result<()> {
        let path = format!("groups/{}.enc", group_id);
        self.delete_file(&path)
    }

    /// Save the last seen Signed Tree Head.
    pub fn save_last_sth<T: Serialize>(&self, sth: &T) -> Result<()> {
        self.write_file("last_sth.enc", sth)
    }

    /// Load the last seen Signed Tree Head.
    pub fn load_last_sth<T: DeserializeOwned>(&self) -> Option<T> {
        self.read_file("last_sth.enc").ok()
    }

    /// Save the server's transparency public key.
    pub fn save_server_transparency_key(&self, pubkey_hex: &str) -> Result<()> {
        self.write_file("server_transparency_key.enc", &pubkey_hex.to_string())
    }

    /// Load the server's transparency public key.
    pub fn load_server_transparency_key(&self) -> Option<String> {
        self.read_file::<String>("server_transparency_key.enc").ok()
    }

    /// Save the server's ML-DSA-87 public key (post-quantum half).
    pub fn save_server_ml_dsa_key(&self, pubkey_hex: &str) -> Result<()> {
        self.write_file("server_ml_dsa_key.enc", &pubkey_hex.to_string())
    }

    /// Load the server's ML-DSA-87 public key.
    pub fn load_server_ml_dsa_key(&self) -> Option<String> {
        self.read_file::<String>("server_ml_dsa_key.enc").ok()
    }

    /// Save the sender certificate received from the server.
    pub fn save_sender_cert<T: Serialize>(&self, cert: &T) -> Result<()> {
        self.write_file("sender_cert.enc", cert)
    }

    /// Load the sender certificate.
    pub fn load_sender_cert<T: DeserializeOwned>(&self) -> Option<T> {
        self.read_file("sender_cert.enc").ok()
    }
}

/// Derive master key from passphrase + salt using argon2id.
fn derive_master_key(passphrase: &str, salt: &[u8; 32]) -> Result<[u8; 32]> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
            .map_err(|e| anyhow!("argon2 params: {}", e))?,
    );

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("argon2 derivation failed: {}", e))?;

    Ok(key)
}

/// Derive a per-file encryption key using HKDF.
fn derive_file_key(master_key: &[u8; 32], file_path: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut key = [0u8; 32];
    hk.expand(file_path.as_bytes(), &mut key)
        .expect("HKDF expand should not fail for 32 bytes");
    key
}

/// Encrypt data with AES-256-GCM. Output: nonce (12 bytes) || ciphertext.
fn encrypt_data(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow!("AES key init: {}", e))?;

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("AES-GCM encrypt: {}", e))?;

    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt data (nonce || ciphertext) with AES-256-GCM.
fn decrypt_data(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 {
        return Err(anyhow!("encrypted data too short"));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow!("AES key init: {}", e))?;

    let nonce = Nonce::from_slice(&data[..12]);
    let ciphertext = &data[12..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("decryption failed — wrong key or corrupted data"))
}
