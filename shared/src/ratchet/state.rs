use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::types::*;

/// A PQ epoch ratchet that we initiated and are still advertising on every outgoing
/// message until the peer acknowledges it (by sending a message at our epoch number or
/// higher). The KEM ciphertext rides on one logical transition, so re-stamping it on each
/// message makes the epoch self-describing and tolerant of out-of-order delivery — any
/// message of the new epoch can drive the peer's transition. `ct`/`epoch_pk` are public.
#[derive(Clone, Serialize, Deserialize)]
pub struct PendingEpoch {
    pub ct: PqCiphertext,
    pub epoch_pk: PqPublicKey,
    pub epoch_number: u32,
}

/// Complete Triple Ratchet state for one session endpoint.
/// Must be stored encrypted (SQLCipher) and zeroized on drop (H3).
#[derive(Clone, Serialize, Deserialize)]
pub struct RatchetState {
    // Identity
    pub local_identity: IdentityPublicKey,
    pub remote_identity: IdentityPublicKey,

    // Layer 3: Epoch ratchet (PQ)
    pub epoch_number: u32,
    pub my_epoch_pk: Option<PqPublicKey>,
    pub my_epoch_sk: Option<PqSecretKey>,
    /// The peer's epoch public key we may encapsulate to next. Set to None once consumed
    /// by an outgoing epoch ratchet — this is the alternation gate: a side may only
    /// initiate an epoch ratchet while it holds a fresh (unconsumed) peer epoch key, which
    /// it regains when the peer initiates an epoch ratchet back. Prevents the same side
    /// from epoch-ratcheting twice in a row against a key the peer has already rotated away.
    pub peer_epoch_pk: Option<PqPublicKey>,
    pub epoch_message_count: u32,
    pub epoch_start_time: u64,
    /// An epoch ratchet we initiated and are still advertising until the peer acks it.
    #[serde(default)]
    pub pending_epoch: Option<PendingEpoch>,

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
    /// SECURITY: The processed_ids window must cover at least as many DH ratchets as
    /// skipped_keys retains (100), otherwise a replayed skipped message could be accepted
    /// after its processed_id is evicted but its skipped key is still present.
    /// We evict processed_ids by DH ratchet number (same unit as skipped_keys) to keep them aligned.
    pub fn cleanup_processed_ids(&mut self) {
        const MAX_PROCESSED: usize = 50_000; // raised from 10K to cover skipped key window

        if self.processed_ids.len() > MAX_PROCESSED {
            // Evict entries older than the skipped_keys cutoff to stay aligned
            let ratchet_cutoff = if self.dh_ratchet_number > 100 {
                self.dh_ratchet_number - 100
            } else {
                0
            };

            // Remove processed_ids that are older than the skipped key retention window
            self.processed_order.retain(|&tuple| {
                if tuple.1 < ratchet_cutoff {
                    self.processed_ids.remove(&tuple);
                    false
                } else {
                    true
                }
            });

            // If still over limit, do FIFO eviction as fallback
            while self.processed_ids.len() > MAX_PROCESSED {
                if let Some(old) = self.processed_order.pop_front() {
                    self.processed_ids.remove(&old);
                } else {
                    break;
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

/// H3: Zeroize all sensitive key material on drop.
/// Cannot use derive(ZeroizeOnDrop) because HashMap/HashSet/VecDeque don't impl Zeroize.
impl Drop for RatchetState {
    fn drop(&mut self) {
        // Symmetric keys
        self.root_key.zeroize();
        if let Some(ref mut k) = self.sending_chain_key { k.zeroize(); }
        if let Some(ref mut k) = self.receiving_chain_key { k.zeroize(); }

        // DH private key
        if let Some(ref mut k) = self.my_dh_private { k.zeroize(); }

        // Header keys
        if let Some(ref mut k) = self.sending_header_key { k.zeroize(); }
        if let Some(ref mut k) = self.receiving_header_key { k.zeroize(); }
        if let Some(ref mut k) = self.next_sending_header_key { k.zeroize(); }
        if let Some(ref mut k) = self.next_receiving_header_key { k.zeroize(); }

        // PQ secret key
        if let Some(ref mut k) = self.my_epoch_sk { k.zeroize(); }

        // Skipped message keys (each MessageKey implements Zeroize)
        for (_, key) in self.skipped_keys.iter_mut() {
            key.zeroize();
        }
    }
}
