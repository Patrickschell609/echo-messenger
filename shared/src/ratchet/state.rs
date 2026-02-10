use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::types::*;

/// Complete Triple Ratchet state for one session endpoint.
/// Must be stored encrypted (SQLCipher) and zeroized when replaced.
#[derive(Clone, Serialize, Deserialize)]
pub struct RatchetState {
    // Identity
    pub local_identity: IdentityPublicKey,
    pub remote_identity: IdentityPublicKey,

    // Layer 3: Epoch ratchet (PQ)
    pub epoch_number: u32,
    pub my_epoch_pk: Option<PqPublicKey>,
    pub my_epoch_sk: Option<PqSecretKey>,
    pub peer_epoch_pk: Option<PqPublicKey>,
    pub epoch_message_count: u32,
    pub epoch_start_time: u64,

    // Layer 2: DH ratchet
    pub dh_ratchet_number: u32,
    pub my_dh_public: PublicKey,
    pub my_dh_private: Option<PrivateKey>,
    pub peer_dh_public: Option<PublicKey>,

    // Layer 1: Symmetric ratchet
    pub root_key: RootKey,
    pub sending_chain_key: Option<ChainKey>,
    pub receiving_chain_key: Option<ChainKey>,
    pub send_message_number: u32,
    pub recv_message_number: u32,
    pub prev_sending_chain_length: u32,

    // Header keys
    pub sending_header_key: Option<HeaderKey>,
    pub receiving_header_key: Option<HeaderKey>,
    pub next_sending_header_key: Option<HeaderKey>,
    pub next_receiving_header_key: Option<HeaderKey>,

    // Skipped message keys for out-of-order delivery
    pub skipped_keys: HashMap<(u32, u32), MessageKey>, // (dh_ratchet, msg_number) -> key

    // Replay protection (HashSet for O(1) lookup, VecDeque for FIFO eviction order)
    pub processed_ids: HashSet<(u32, u32, u32)>, // (epoch, dh_ratchet, msg_number)
    #[serde(default)]
    pub processed_order: VecDeque<(u32, u32, u32)>, // insertion order for eviction
}

impl RatchetState {
    /// Check if it's time for a PQ epoch ratchet.
    pub fn needs_epoch_ratchet(&self) -> bool {
        if self.epoch_message_count >= PQ_RATCHET_INTERVAL {
            return true;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now - self.epoch_start_time >= PQ_RATCHET_TIME_INTERVAL
    }

    /// Check if we've stored too many skipped keys.
    pub fn has_too_many_skipped(&self) -> bool {
        self.skipped_keys.len() as u32 > MAX_SKIP
    }

    /// Clean up old skipped keys (older than 30 days by ratchet number).
    pub fn cleanup_skipped_keys(&mut self) {
        if self.dh_ratchet_number > 100 {
            let cutoff = self.dh_ratchet_number - 100;
            self.skipped_keys.retain(|&(ratchet, _), _| ratchet >= cutoff);
        }
    }

    /// Clean up processed IDs to prevent unbounded growth.
    pub fn cleanup_processed_ids(&mut self) {
        const MAX_PROCESSED: usize = 10_000;
        if self.processed_ids.len() > MAX_PROCESSED {
            let drain_count = self.processed_ids.len() - MAX_PROCESSED / 2;
            for _ in 0..drain_count {
                if let Some(old) = self.processed_order.pop_front() {
                    self.processed_ids.remove(&old);
                }
            }
        }
    }

    /// Check if a message has already been processed (replay protection). O(1).
    pub fn is_replay(&self, epoch: u32, dh_ratchet: u32, msg_number: u32) -> bool {
        self.processed_ids.contains(&(epoch, dh_ratchet, msg_number))
    }

    /// Mark a message as processed.
    pub fn mark_processed(&mut self, epoch: u32, dh_ratchet: u32, msg_number: u32) {
        let tuple = (epoch, dh_ratchet, msg_number);
        if self.processed_ids.insert(tuple) {
            self.processed_order.push_back(tuple);
        }
        self.cleanup_processed_ids();
    }
}
