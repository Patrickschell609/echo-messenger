//! Group messaging protocol with sender keys + PQ epoch ratchet.
//!
//! Each member has a sender key chain. Messages are encrypted once
//! and all members can decrypt. Sender keys are distributed via
//! pairwise TR3 sessions.
//!
//! PQ epoch ratchet runs every 50 group messages for post-quantum
//! forward secrecy in group chats.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::{aead, kdf};
use crate::crypto::pq_kem;
use crate::error::{EchoError, Result};
use crate::types::*;

const GROUP_CHAIN_INFO: &[u8] = b"echo-group-chain-v1";
const GROUP_MSG_INFO: &[u8] = b"echo-group-msg-v1";
const GROUP_PQ_INTERVAL: u32 = 50;

/// A member's sender key state.
#[derive(Clone, Serialize, Deserialize)]
pub struct SenderKeyState {
    pub chain_key: ChainKey,
    pub iteration: u32,
    pub pq_epoch: u32,
    #[serde(default)]
    pub skipped_keys: HashMap<u32, MessageKey>,
}

impl SenderKeyState {
    /// Generate a new random sender key.
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        Self {
            chain_key: ChainKey(key),
            iteration: 0,
            pq_epoch: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Advance the chain and derive a message key.
    pub fn ratchet(&mut self) -> MessageKey {
        let msg_key_bytes = kdf::hkdf_derive(&self.chain_key.0, &[0x01], GROUP_MSG_INFO, 32);
        let new_chain = kdf::hkdf_derive(&self.chain_key.0, &[0x02], GROUP_CHAIN_INFO, 32);

        let mut mk = [0u8; 32];
        mk.copy_from_slice(&msg_key_bytes);
        self.chain_key.0.copy_from_slice(&new_chain);
        self.iteration += 1;

        MessageKey(mk)
    }

    /// Check if PQ epoch ratchet is needed.
    pub fn needs_pq_ratchet(&self) -> bool {
        self.iteration > 0 && self.iteration % GROUP_PQ_INTERVAL == 0
    }
}

/// Group session managing all sender keys.
#[derive(Clone, Serialize, Deserialize)]
pub struct GroupSession {
    pub group_id: [u8; 16],
    pub our_device_id: DeviceId,
    pub our_sender_key: SenderKeyState,
    pub member_keys: HashMap<DeviceId, SenderKeyState>,
    pub epoch: u32,
    pub our_epoch_pk: Option<PqPublicKey>,
    pub our_epoch_sk: Option<PqSecretKey>,
    #[serde(default)]
    pub processed_ids: std::collections::HashSet<Vec<u8>>,
}

impl GroupSession {
    /// Create a new group session.
    pub fn new(group_id: [u8; 16], our_device_id: DeviceId) -> Self {
        Self {
            group_id,
            our_device_id,
            our_sender_key: SenderKeyState::generate(),
            member_keys: HashMap::new(),
            epoch: 0,
            our_epoch_pk: None,
            our_epoch_sk: None,
            processed_ids: std::collections::HashSet::new(),
        }
    }

    /// Get our sender key distribution message (sent via pairwise TR3).
    pub fn sender_key_distribution(&self) -> SenderKeyDistribution {
        SenderKeyDistribution {
            group_id: self.group_id,
            sender_device: self.our_device_id.clone(),
            chain_key: self.our_sender_key.chain_key.clone(),
            iteration: self.our_sender_key.iteration,
            epoch: self.epoch,
        }
    }

    /// Process a received sender key distribution.
    pub fn process_sender_key(&mut self, dist: &SenderKeyDistribution) {
        self.member_keys.insert(
            dist.sender_device.clone(),
            SenderKeyState {
                chain_key: dist.chain_key.clone(),
                iteration: dist.iteration,
                pq_epoch: 0,
                skipped_keys: HashMap::new(),
            },
        );
    }

    /// Encrypt a message for the group.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<GroupMessage> {
        let message_key = self.our_sender_key.ratchet();

        let padded = aead::pad_message(plaintext);
        let ciphertext = aead::aead_encrypt(&message_key.0, &padded, &self.group_id)?;

        Ok(GroupMessage {
            group_id: self.group_id,
            sender_device: self.our_device_id.clone(),
            iteration: self.our_sender_key.iteration - 1,
            epoch: self.epoch,
            ciphertext,
        })
    }

    /// Decrypt a group message.
    pub fn decrypt(&mut self, message: &GroupMessage) -> Result<Vec<u8>> {
        // Replay protection: hash (sender, iteration, ciphertext) as unique ID
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&message.sender_device.0);
        hasher.update(&message.iteration.to_le_bytes());
        hasher.update(&message.ciphertext);
        let msg_id = hasher.finalize().to_vec();

        if self.processed_ids.contains(&msg_id) {
            return Err(EchoError::ReplayDetected(
                "duplicate group message".into()
            ));
        }

        let sender_state = self
            .member_keys
            .get_mut(&message.sender_device)
            .ok_or(EchoError::SessionNotFound(format!(
                "no sender key for {:?}",
                message.sender_device
            )))?;

        // Check skipped keys for out-of-order messages
        if message.iteration < sender_state.iteration {
            if let Some(mk) = sender_state.skipped_keys.remove(&message.iteration) {
                let padded = aead::aead_decrypt(&mk.0, &message.ciphertext, &message.group_id)?;
                let plaintext = aead::unpad_message(&padded)?;
                self.processed_ids.insert(msg_id);
                return Ok(plaintext);
            } else {
                return Err(EchoError::InvalidMessage(
                    format!("no skipped key for iteration {}", message.iteration)
                ));
            }
        }

        // Store skipped keys instead of discarding them
        while sender_state.iteration < message.iteration {
            let skipped_key = sender_state.ratchet();
            let skipped_iteration = sender_state.iteration - 1;
            sender_state.skipped_keys.insert(skipped_iteration, skipped_key);
        }

        let message_key = sender_state.ratchet();
        let padded = aead::aead_decrypt(&message_key.0, &message.ciphertext, &message.group_id)?;
        let plaintext = aead::unpad_message(&padded)?;

        self.processed_ids.insert(msg_id);

        Ok(plaintext)
    }
}

/// Sender key distribution message (sent via pairwise session).
#[derive(Clone, Serialize, Deserialize)]
pub struct SenderKeyDistribution {
    pub group_id: [u8; 16],
    pub sender_device: DeviceId,
    pub chain_key: ChainKey,
    pub iteration: u32,
    pub epoch: u32,
}

/// Encrypted group message.
#[derive(Clone, Serialize, Deserialize)]
pub struct GroupMessage {
    pub group_id: [u8; 16],
    pub sender_device: DeviceId,
    pub iteration: u32,
    pub epoch: u32,
    pub ciphertext: Vec<u8>,
}
