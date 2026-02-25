//! Local identity storage: keys, sessions, ratchet state.
//! Stores as JSON files under a configurable base directory.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use echo_crypto::crypto::ed25519::Ed25519KeyPair;
use echo_crypto::crypto::kdf;
use echo_crypto::crypto::pq_kem;
use echo_crypto::crypto::x25519::X25519KeyPair;
use echo_crypto::ratchet::state::RatchetState;
use echo_crypto::ratchet::x4dh::X4DHInitResult;
use echo_crypto::sealed_sender::SenderCertificate;
use echo_crypto::types::*;

/// Number of one-time prekeys to generate per upload.
const ONE_TIME_PREKEY_COUNT: u32 = 100;

// ─── Key material (in-memory, not serialized directly) ───

pub struct KeyMaterial {
    pub identity_ed: Ed25519KeyPair,
    pub identity_dh: X25519KeyPair,
    pub signed_prekey: X25519KeyPair,
    pub signed_prekey_id: u32,
    pub signed_prekey_sig: Vec<u8>,
    pub pq_pk: PqPublicKey,
    pub pq_sk: PqSecretKey,
    pub pq_prekey_id: u32,
    pub pq_prekey_sig: Vec<u8>,
    pub one_time_prekeys: Vec<(u32, X25519KeyPair)>,
}

impl KeyMaterial {
    /// Generate additional one-time prekeys starting from `start_id`.
    pub fn generate_additional_prekeys(start_id: u32, count: u32) -> Vec<(u32, X25519KeyPair)> {
        (0..count)
            .map(|i| (start_id + i, X25519KeyPair::generate()))
            .collect()
    }

    /// Rotate the signed prekey: generate new X25519 key, sign with identity Ed25519.
    pub fn rotate_signed_prekey(
        identity_ed: &Ed25519KeyPair,
        new_id: u32,
    ) -> (X25519KeyPair, Vec<u8>) {
        let new_spk = X25519KeyPair::generate();
        let sig = identity_ed.sign(&new_spk.public_key().0);
        (new_spk, sig)
    }

    /// Rotate the PQ prekey: generate new ML-KEM keypair, sign public key with identity Ed25519.
    pub fn rotate_pq_prekey(
        identity_ed: &Ed25519KeyPair,
        _new_id: u32,
    ) -> (PqPublicKey, PqSecretKey, Vec<u8>) {
        let (pq_pk, pq_sk) = pq_kem::pq_keygen();
        let sig = identity_ed.sign(&pq_pk.0);
        (pq_pk, pq_sk, sig)
    }

    pub fn generate() -> Self {
        let identity_ed = Ed25519KeyPair::generate();
        let identity_dh = X25519KeyPair::generate();
        let signed_prekey = X25519KeyPair::generate();
        let signed_prekey_id = 1;

        let signed_prekey_sig = identity_ed.sign(&signed_prekey.public_key().0);

        let (pq_pk, pq_sk) = pq_kem::pq_keygen();
        let pq_prekey_id = 1;
        let pq_prekey_sig = identity_ed.sign(&pq_pk.0);

        let one_time_prekeys: Vec<(u32, X25519KeyPair)> = (0..ONE_TIME_PREKEY_COUNT)
            .map(|i| (i + 1, X25519KeyPair::generate()))
            .collect();

        Self {
            identity_ed,
            identity_dh,
            signed_prekey,
            signed_prekey_id,
            signed_prekey_sig,
            pq_pk,
            pq_sk,
            pq_prekey_id,
            pq_prekey_sig,
            one_time_prekeys,
        }
    }
}

// ─── Persistent identity state ───

#[derive(Serialize, Deserialize, Clone)]
pub struct IdentityState {
    pub account_id: Uuid,
    pub device_id: Uuid,
    pub identity_ed_private: Vec<u8>,
    pub identity_ed_public: Vec<u8>,
    pub identity_dh_private: Vec<u8>,
    pub identity_dh_public: Vec<u8>,
    pub signed_prekey_private: Vec<u8>,
    pub signed_prekey_public: Vec<u8>,
    pub signed_prekey_id: u32,
    pub pq_pk: Vec<u8>,
    pub pq_sk: Vec<u8>,
    pub pq_prekey_id: u32,
    #[serde(default)]
    pub one_time_prekeys: Vec<(u32, Vec<u8>)>,
    /// Timestamp of last key rotation (unix seconds)
    #[serde(default)]
    pub last_rotation_time: Option<u64>,
    /// Previous signed prekey private key (grace period)
    #[serde(default)]
    pub prev_signed_prekey_private: Option<Vec<u8>>,
    /// Previous signed prekey ID
    #[serde(default)]
    pub prev_signed_prekey_id: Option<u32>,
    /// Previous PQ secret key (grace period)
    #[serde(default)]
    pub prev_pq_sk: Option<Vec<u8>>,
    /// Previous PQ prekey ID
    #[serde(default)]
    pub prev_pq_prekey_id: Option<u32>,
    /// Expiry timestamp for previous keys (unix seconds)
    #[serde(default)]
    pub prev_key_expiry: Option<u64>,
    /// Human-friendly short code (e.g. "A7X2-KM9P")
    #[serde(default)]
    pub short_code: Option<String>,
}

impl Drop for IdentityState {
    fn drop(&mut self) {
        self.identity_ed_private.zeroize();
        self.identity_ed_public.zeroize();
        self.identity_dh_private.zeroize();
        self.identity_dh_public.zeroize();
        self.signed_prekey_private.zeroize();
        self.signed_prekey_public.zeroize();
        self.pq_pk.zeroize();
        self.pq_sk.zeroize();
        for (_, key_bytes) in &mut self.one_time_prekeys {
            key_bytes.zeroize();
        }
        if let Some(ref mut key) = self.prev_signed_prekey_private {
            key.zeroize();
        }
        if let Some(ref mut key) = self.prev_pq_sk {
            key.zeroize();
        }
    }
}

impl IdentityState {
    pub fn reconstruct_keys(&self) -> ReconstructedKeys {
        let mut ed_bytes = [0u8; 32];
        ed_bytes.copy_from_slice(&self.identity_ed_private);
        let identity_ed = Ed25519KeyPair::from_private_bytes(ed_bytes);

        let mut dh_bytes = [0u8; 32];
        dh_bytes.copy_from_slice(&self.identity_dh_private);
        let identity_dh = X25519KeyPair::from_private_bytes(dh_bytes);

        let mut spk_bytes = [0u8; 32];
        spk_bytes.copy_from_slice(&self.signed_prekey_private);
        let signed_prekey = X25519KeyPair::from_private_bytes(spk_bytes);

        let one_time_prekeys: Vec<(u32, X25519KeyPair)> = self
            .one_time_prekeys
            .iter()
            .map(|(id, bytes)| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                (*id, X25519KeyPair::from_private_bytes(arr))
            })
            .collect();

        ReconstructedKeys {
            identity_ed,
            identity_dh,
            signed_prekey,
            pq_sk: PqSecretKey(self.pq_sk.clone()),
            one_time_prekeys,
        }
    }
}

pub struct ReconstructedKeys {
    pub identity_ed: Ed25519KeyPair,
    pub identity_dh: X25519KeyPair,
    pub signed_prekey: X25519KeyPair,
    pub pq_sk: PqSecretKey,
    pub one_time_prekeys: Vec<(u32, X25519KeyPair)>,
}

// ─── Session metadata ───

#[derive(Serialize, Deserialize, Clone)]
pub struct SessionMeta {
    pub recipient_device_id: Uuid,
    pub recipient_identity_key: Vec<u8>,
    pub recipient_dh_key: PublicKey,
    pub ephemeral_public: Vec<u8>,
    pub pq_ciphertext: Vec<u8>,
    pub used_one_time_prekey_id: Option<u32>,
    #[serde(default = "default_true")]
    pub needs_prekey_message: bool,
}

fn default_true() -> bool {
    true
}

// ─── Identity store (encrypted via EncryptedVault) ───

pub struct IdentityStore {
    name: String,
    dir: PathBuf,
    vault: crate::storage::EncryptedVault,
}

impl IdentityStore {
    /// Create a store under ~/.echo/<name>/ with vault encryption.
    /// Passphrase is required: set ECHO_PASSPHRASE env var, or pass directly.
    pub fn new(name: &str) -> Result<Self> {
        let base = dirs::home_dir()
            .ok_or_else(|| anyhow!("cannot determine home directory"))?
            .join(".echo");
        Self::with_base_dir(name, &base)
    }

    /// Create a store under a custom base directory.
    pub fn with_base_dir(name: &str, base: &Path) -> Result<Self> {
        let dir = base.join(name);
        std::fs::create_dir_all(&dir)?;
        let vault_dir = dir.join("vault");
        let mut vault = crate::storage::EncryptedVault::new(&vault_dir);

        // Prompt for passphrase — never read from env vars (leaked via /proc/pid/environ)
        eprint!("Vault passphrase: ");
        let mut passphrase = String::new();
        std::io::stdin().read_line(&mut passphrase).unwrap_or_default();
        let passphrase = passphrase.trim().to_string();

        if vault_dir.join("salt.bin").exists() {
            vault.unlock(&passphrase)?;
        } else {
            vault.create(&passphrase)?;
        }

        // Migrate legacy plaintext identity.json if it exists
        let legacy_path = dir.join("identity.json");
        if legacy_path.exists() && !vault_dir.join("identity.enc").exists() {
            eprintln!("[ECHO] Migrating plaintext identity to encrypted vault...");
            let json = std::fs::read_to_string(&legacy_path)?;
            let state: IdentityState = serde_json::from_str(&json)?;
            vault.write_file("identity.enc", &state)?;
            // Shred legacy file: overwrite with zeros then delete
            let len = std::fs::metadata(&legacy_path)?.len() as usize;
            std::fs::write(&legacy_path, vec![0u8; len])?;
            std::fs::remove_file(&legacy_path)?;
            eprintln!("[ECHO] Migration complete. Plaintext identity deleted.");
        }

        Ok(Self { name: name.to_string(), dir, vault })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }

    pub fn save(&self, account_id: Uuid, device_id: Uuid, keys: &KeyMaterial) -> Result<()> {
        let state = IdentityState {
            account_id,
            device_id,
            identity_ed_private: keys.identity_ed.private_key_bytes().0.to_vec(),
            identity_ed_public: keys.identity_ed.public_key().0.to_vec(),
            identity_dh_private: keys.identity_dh.private_key_bytes().0.to_vec(),
            identity_dh_public: keys.identity_dh.public_key().0.to_vec(),
            signed_prekey_private: keys.signed_prekey.private_key_bytes().0.to_vec(),
            signed_prekey_public: keys.signed_prekey.public_key().0.to_vec(),
            signed_prekey_id: keys.signed_prekey_id,
            pq_pk: keys.pq_pk.0.clone(),
            pq_sk: keys.pq_sk.0.clone(),
            pq_prekey_id: keys.pq_prekey_id,
            one_time_prekeys: keys
                .one_time_prekeys
                .iter()
                .map(|(id, kp)| (*id, kp.private_key_bytes().0.to_vec()))
                .collect(),
            last_rotation_time: None,
            prev_signed_prekey_private: None,
            prev_signed_prekey_id: None,
            prev_pq_sk: None,
            prev_pq_prekey_id: None,
            prev_key_expiry: None,
            short_code: None,
        };

        self.vault.write_file("identity.enc", &state)?;
        Ok(())
    }

    pub fn load(&self) -> Result<IdentityState> {
        self.vault.read_file::<IdentityState>("identity.enc")
            .map_err(|_| anyhow!("identity not found — run `echo register` first"))
    }

    pub fn save_session(
        &self,
        recipient_device_id: Uuid,
        ratchet_state: &RatchetState,
        init_result: &X4DHInitResult,
        recipient_dh_key: &PublicKey,
    ) -> Result<()> {
        let ratchet_path = format!("sessions/{}.ratchet.enc", recipient_device_id);
        self.vault.write_file(&ratchet_path, ratchet_state)?;

        let meta = SessionMeta {
            recipient_device_id,
            recipient_identity_key: ratchet_state.remote_identity.0.to_vec(),
            recipient_dh_key: recipient_dh_key.clone(),
            ephemeral_public: init_result.ephemeral_public.0.to_vec(),
            pq_ciphertext: init_result.pq_ciphertext.0.clone(),
            used_one_time_prekey_id: init_result.used_one_time_prekey_id,
            needs_prekey_message: true,
        };
        let meta_path = format!("sessions/{}.meta.enc", recipient_device_id);
        self.vault.write_file(&meta_path, &meta)?;

        Ok(())
    }

    pub fn save_session_with_meta(
        &self,
        recipient_device_id: Uuid,
        ratchet_state: &RatchetState,
        meta: &SessionMeta,
    ) -> Result<()> {
        let ratchet_path = format!("sessions/{}.ratchet.enc", recipient_device_id);
        self.vault.write_file(&ratchet_path, ratchet_state)?;

        let meta_path = format!("sessions/{}.meta.enc", recipient_device_id);
        self.vault.write_file(&meta_path, meta)?;

        Ok(())
    }

    pub fn load_session(&self, recipient_device_id: Uuid) -> Result<(RatchetState, SessionMeta)> {
        let ratchet_path = format!("sessions/{}.ratchet.enc", recipient_device_id);
        let ratchet_state: RatchetState = self.vault.read_file(&ratchet_path)
            .map_err(|_| anyhow!("no session for device {}", recipient_device_id))?;

        let meta_path = format!("sessions/{}.meta.enc", recipient_device_id);
        let meta: SessionMeta = self.vault.read_file(&meta_path)
            .map_err(|_| anyhow!("no session meta for device {}", recipient_device_id))?;

        Ok((ratchet_state, meta))
    }

    pub fn update_session(
        &self,
        recipient_device_id: Uuid,
        ratchet_state: &RatchetState,
    ) -> Result<()> {
        let ratchet_path = format!("sessions/{}.ratchet.enc", recipient_device_id);
        self.vault.write_file(&ratchet_path, ratchet_state)?;
        Ok(())
    }

    /// List all session device UUIDs
    pub fn list_sessions(&self) -> Result<Vec<Uuid>> {
        let sessions_dir = self.dir.join("vault").join("sessions");
        if !sessions_dir.exists() {
            return Ok(Vec::new());
        }
        let mut uuids = Vec::new();
        for entry in std::fs::read_dir(&sessions_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".meta.enc") {
                let uuid_str = name.trim_end_matches(".meta.enc");
                if let Ok(uuid) = uuid_str.parse::<Uuid>() {
                    uuids.push(uuid);
                }
            }
        }
        Ok(uuids)
    }

    pub fn save_last_sth(&self, sth: &echo_crypto::transparency::SignedTreeHead) -> Result<()> {
        self.vault.write_file("last_sth.enc", sth)?;
        Ok(())
    }

    pub fn load_last_sth(&self) -> Option<echo_crypto::transparency::SignedTreeHead> {
        self.vault.read_file("last_sth.enc").ok()
    }

    pub fn clear_last_sth(&self) -> Result<()> {
        let path = self.dir.join("vault").join("last_sth.enc");
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }

    pub fn save_server_transparency_key(&self, pubkey_hex: &str) -> Result<()> {
        self.vault.write_file("server_transparency_key.enc", &pubkey_hex.to_string())?;
        Ok(())
    }

    pub fn load_server_transparency_key(&self) -> Option<String> {
        self.vault.read_file::<String>("server_transparency_key.enc").ok()
    }
}

// ─── Helper functions ───

pub fn build_initiator_state(
    keys: &ReconstructedKeys,
    bundle: &PrekeyBundle,
    init: &X4DHInitResult,
) -> RatchetState {
    let (pq_pk, pq_sk) = pq_kem::pq_keygen();
    let dh = X25519KeyPair::generate();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    RatchetState {
        local_identity: keys.identity_ed.public_key(),
        remote_identity: bundle.identity_key.clone(),
        epoch_number: 0,
        my_epoch_pk: Some(pq_pk),
        my_epoch_sk: Some(pq_sk),
        peer_epoch_pk: Some(bundle.pq_prekey.clone()),
        epoch_message_count: 0,
        epoch_start_time: now,
        dh_ratchet_number: 0,
        my_dh_public: dh.public_key(),
        my_dh_private: Some(dh.private_key_bytes()),
        peer_dh_public: Some(bundle.signed_prekey.clone()),
        root_key: init.root_key.clone(),
        sending_chain_key: Some(init.chain_key.clone()),
        receiving_chain_key: None,
        send_message_number: 0,
        recv_message_number: 0,
        prev_sending_chain_length: 0,
        // Derive initial header keys from X4DH root key (AV-07: no plaintext headers)
        sending_header_key: Some(kdf::derive_header_key(&init.root_key, true)),
        receiving_header_key: Some(kdf::derive_header_key(&init.root_key, false)),
        next_sending_header_key: Some(kdf::derive_header_key(&init.root_key, true)),
        next_receiving_header_key: Some(kdf::derive_header_key(&init.root_key, false)),
        skipped_keys: HashMap::new(),
        processed_ids: std::collections::HashSet::new(),
        processed_order: std::collections::VecDeque::new(),
    }
}

pub fn build_sender_cert(state: &IdentityState) -> SenderCertificate {
    let mut ik = [0u8; 32];
    ik.copy_from_slice(&state.identity_ed_public);

    let mut device_bytes = [0u8; 16];
    device_bytes.copy_from_slice(state.device_id.as_bytes());

    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 86400;

    let mut cert = SenderCertificate {
        sender_identity: IdentityPublicKey(ik),
        sender_device_id: DeviceId(device_bytes),
        expiry,
        server_signature: vec![0u8; 64], // POC placeholder (no server sig)
        sender_signature: vec![],
    };

    // Counter-sign with our Ed25519 key (C1)
    let mut ed_priv = [0u8; 32];
    ed_priv.copy_from_slice(&state.identity_ed_private);
    echo_crypto::sealed_sender::countersign_sender_cert(&mut cert, &ed_priv);
    ed_priv.zeroize();

    cert
}

/// C3/C4: Sign our identity_dh_key with our Ed25519 identity key.
/// Returns the signature binding the DH key to Ed25519 identity.
pub fn sign_identity_dh_binding(state: &IdentityState) -> Vec<u8> {
    use echo_crypto::crypto::ed25519::Ed25519KeyPair;

    let mut ed_bytes = [0u8; 32];
    ed_bytes.copy_from_slice(&state.identity_ed_private);
    let ed_key = Ed25519KeyPair::from_private_bytes(ed_bytes);
    ed_bytes.zeroize();

    let mut msg = Vec::new();
    msg.extend_from_slice(b"echo-dh-binding:");
    msg.extend_from_slice(&state.identity_dh_public);
    ed_key.sign(&msg)
}
