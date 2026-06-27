//! Triple Ratchet session: encrypt and decrypt messages.
//!
//! This is the main interface. It manages all three ratchet layers
//! and handles out-of-order message delivery.

use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroize;

use crate::crypto::aead;
use crate::crypto::kdf;
use crate::crypto::pq_kem;
use crate::crypto::x25519::X25519KeyPair;
use crate::error::{EchoError, Result};
use crate::ratchet::state::RatchetState;
use crate::types::*;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Encrypted message output from the Triple Ratchet.
pub struct EncryptedMessage {
    pub header: MessageHeader,
    pub encrypted_header: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Decrypted message output.
pub struct DecryptedMessage {
    pub plaintext: Vec<u8>,
    pub sender_epoch: u32,
    pub sender_dh_ratchet: u32,
    pub message_number: u32,
}

pub struct TripleRatchetSession {
    state: RatchetState,
}

impl TripleRatchetSession {
    /// Create a new session from initial state (after X4DH).
    pub fn new(state: RatchetState) -> Self {
        Self { state }
    }

    /// Encrypt a plaintext message.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptedMessage> {
        // Decide on the ratchet for this message (Layers 2 + 3).
        //
        // An epoch ratchet is due when needs_epoch_ratchet() fires AND we hold the peer's
        // epoch public key. The initiator always has it (from the prekey bundle); the
        // responder learns it from the initiator's first epoch ratchet. If we don't have
        // it yet we DEFER (keep sending normally) rather than fail — bidirectional traffic
        // delivers the peer's epoch key shortly and the ratchet then fires.
        let epoch_due =
            self.state.needs_epoch_ratchet() && self.state.peer_epoch_pk.is_some();

        let (epoch_ct, new_epoch_pk) = if epoch_due {
            // Epoch ratchet = a DH ratchet step with the PQ secret folded into the root.
            let (ct, pk) = self.dh_ratchet_send_epoch()?;
            (Some(ct), Some(pk))
        } else {
            // Lazy DH ratchet: only on the first send after a receive cleared the chain.
            if self.state.sending_chain_key.is_none() {
                if let Some(ref peer_dh) = self.state.peer_dh_public.clone() {
                    self.dh_ratchet_send(peer_dh, None)?;
                }
            }
            (None, None)
        };

        // Advance symmetric chain (Layer 1)
        let chain_key = self
            .state
            .sending_chain_key
            .as_ref()
            .ok_or(EchoError::ChainExhausted)?;
        let (new_chain_key, message_key) = kdf::kdf_chain(chain_key);
        self.state.sending_chain_key = Some(new_chain_key);

        // Build header
        let header = MessageHeader {
            message_type: if epoch_ct.is_some() {
                MessageType::PqEpochUpdate
            } else {
                MessageType::Normal
            },
            dh_public: self.state.my_dh_public.clone(),
            dh_ratchet_number: self.state.dh_ratchet_number,
            prev_chain_length: self.state.prev_sending_chain_length,
            message_number: self.state.send_message_number,
            epoch_number: self.state.epoch_number,
            epoch_ciphertext: epoch_ct,
            new_epoch_public: new_epoch_pk,
        };

        // Serialize header for AAD binding
        let header_bytes =
            bincode::serialize(&header).map_err(|e| EchoError::SerializationError(e.to_string()))?;

        // Encrypt header with header key
        let encrypted_header = match &self.state.sending_header_key {
            Some(hk) => aead::aead_encrypt(&hk.0, &header_bytes, b"echo-header")?,
            None => header_bytes.clone(), // First message - header sent in prekey message
        };

        // Pad and encrypt plaintext
        let padded = aead::pad_message(plaintext);
        let ciphertext = aead::aead_encrypt(&message_key.0, &padded, &header_bytes)?;

        // Advance counter
        self.state.send_message_number += 1;
        self.state.epoch_message_count += 1;

        Ok(EncryptedMessage {
            header,
            encrypted_header,
            ciphertext,
        })
    }

    /// Decrypt a received message.
    pub fn decrypt(&mut self, message: &EncryptedMessage) -> Result<DecryptedMessage> {
        let header = &message.header;

        // Replay protection
        if self.state.is_replay(
            header.epoch_number,
            header.dh_ratchet_number,
            header.message_number,
        ) {
            return Err(EchoError::ReplayDetected(format!(
                "epoch={}, ratchet={}, msg={}",
                header.epoch_number, header.dh_ratchet_number, header.message_number
            )));
        }

        // Serialize header for AAD binding (needed for all decrypt paths)
        let header_bytes = bincode::serialize(header)
            .map_err(|e| EchoError::SerializationError(e.to_string()))?;

        // FIX: Try skipped keys FIRST (before any state changes).
        // Use header.dh_ratchet_number (sender's chain ID) for lookup.
        let skip_key = (header.dh_ratchet_number, header.message_number);
        if let Some(mk) = self.state.skipped_keys.remove(&skip_key) {
            let padded = aead::aead_decrypt(&mk.0, &message.ciphertext, &header_bytes)?;
            let plaintext = aead::unpad_message(&padded)?;

            self.state.mark_processed(
                header.epoch_number,
                header.dh_ratchet_number,
                header.message_number,
            );

            return Ok(DecryptedMessage {
                plaintext,
                sender_epoch: header.epoch_number,
                sender_dh_ratchet: header.dh_ratchet_number,
                message_number: header.message_number,
            });
        }

        // Is this an epoch ratchet message (Layer 3)?
        let epoch = match (&header.epoch_ciphertext, &header.new_epoch_public) {
            (Some(ct), Some(pk)) => {
                if header.epoch_number != self.state.epoch_number + 1 {
                    return Err(EchoError::InvalidMessage(format!(
                        "unexpected epoch number: got {}, expected {}",
                        header.epoch_number,
                        self.state.epoch_number + 1
                    )));
                }
                Some((ct.clone(), pk.clone()))
            }
            _ => None,
        };

        // Does the peer's DH public differ from what we have? (Layer 2 trigger.)
        let need_dh_ratchet = self
            .state
            .peer_dh_public
            .as_ref()
            .map(|pk| pk != &header.dh_public)
            .unwrap_or(true);

        if let Some((ct, new_pk)) = epoch {
            // M1 invariant: the sender folds the PQ secret into a DH ratchet step, so an
            // epoch message MUST carry a changed DH public. Otherwise the PQ secret could
            // not have reached the chain keys — fail-stop rather than desync.
            if !need_dh_ratchet {
                return Err(EchoError::InvalidMessage(
                    "epoch ratchet received without paired DH change (violates M1 invariant)"
                        .into(),
                ));
            }

            // Decapsulate the PQ secret and fold it into the DH ratchet's root step, so
            // both sides derive identical chains from a shared root (mirror of
            // dh_ratchet_send_epoch). Requires our epoch secret key to be initialized.
            let our_sk = self
                .state
                .my_epoch_sk
                .as_ref()
                .ok_or(EchoError::PqKemError("no local PQ secret key".into()))?;
            let mut ss = pq_kem::pq_decapsulate(&ct, our_sk)?;

            if header.prev_chain_length > self.state.recv_message_number {
                self.skip_message_keys(header.prev_chain_length)?;
            }
            self.dh_ratchet_receive(&header.dh_public, Some(&ss))?;
            ss.zeroize(); // M4: zeroize PQ shared secret

            // Adopt the peer's new epoch key, rotate ours, advance + reset bookkeeping.
            self.state.peer_epoch_pk = Some(new_pk);
            let (np, nsk) = pq_kem::pq_keygen();
            self.state.my_epoch_pk = Some(np);
            self.state.my_epoch_sk = Some(nsk);
            self.state.epoch_number += 1;
            self.state.epoch_message_count = 0;
            self.state.epoch_start_time = now_secs();
        } else if need_dh_ratchet {
            // Store remaining skipped keys from the OLD chain before rotating it.
            if header.prev_chain_length > self.state.recv_message_number {
                self.skip_message_keys(header.prev_chain_length)?;
            }
            self.dh_ratchet_receive(&header.dh_public, None)?;
        }

        // Skip ahead if needed
        if header.message_number > self.state.recv_message_number {
            self.skip_message_keys(header.message_number)?;
        }

        // Decrypt with current chain
        let chain_key = self
            .state
            .receiving_chain_key
            .as_ref()
            .ok_or(EchoError::ChainExhausted)?;
        let (new_chain_key, message_key) = kdf::kdf_chain(chain_key);
        self.state.receiving_chain_key = Some(new_chain_key);
        self.state.recv_message_number += 1;

        let padded = aead::aead_decrypt(&message_key.0, &message.ciphertext, &header_bytes)?;
        let plaintext = aead::unpad_message(&padded)?;

        self.state.mark_processed(
            header.epoch_number,
            header.dh_ratchet_number,
            header.message_number,
        );

        Ok(DecryptedMessage {
            plaintext,
            sender_epoch: header.epoch_number,
            sender_dh_ratchet: header.dh_ratchet_number,
            message_number: header.message_number,
        })
    }

    /// Perform a DH ratchet step for sending (Layer 2), optionally folding in a PQ epoch
    /// secret (Layer 3). When `pq_ss` is `Some`, the KEM secret is mixed into the SAME
    /// root KDF as the DH output (`kdf_root_combined`) so both sides derive identical
    /// chains — see `dh_ratchet_receive`. Lazy ratchet: called on the first send after a
    /// receive (when the sending chain was cleared) or when an epoch ratchet is due.
    fn dh_ratchet_send(&mut self, peer_dh: &PublicKey, pq_ss: Option<&[u8]>) -> Result<()> {
        self.state.prev_sending_chain_length = self.state.send_message_number;
        self.state.send_message_number = 0;

        // Generate new DH key pair
        let new_dh = X25519KeyPair::generate();
        let mut dh_output = new_dh.dh(peer_dh)?;

        // Derive sending chain from root key + DH output (+ PQ secret on an epoch step)
        let (new_root, new_send_chain) = match pq_ss {
            Some(ss) => kdf::kdf_root_combined(&self.state.root_key, &dh_output, ss),
            None => kdf::kdf_root(&self.state.root_key, &dh_output),
        };
        dh_output.zeroize(); // M2: zeroize DH shared secret
        self.state.root_key = new_root;
        self.state.sending_chain_key = Some(new_send_chain);

        // Update header keys
        self.state.sending_header_key = self.state.next_sending_header_key.take();
        self.state.next_sending_header_key =
            Some(kdf::derive_header_key(&self.state.root_key, true));

        self.state.my_dh_public = new_dh.public_key();
        self.state.my_dh_private = Some(new_dh.private_key_bytes());
        self.state.dh_ratchet_number += 1;

        Ok(())
    }

    /// Perform a DH ratchet step on receive (Layer 2), optionally folding in a PQ epoch
    /// secret (Layer 3). LAZY ratchet: we derive ONLY the new receiving chain here and
    /// clear the sending chain, so our own next send performs its DH ratchet from a root
    /// the peer already shares. The previous (eager) design pre-derived a new sending
    /// chain here, which left the two parties' roots one KDF-step apart and desynced the
    /// PQ epoch ratchet whenever it fired after a turn-around (bug #3, Jun 27).
    ///
    /// When `pq_ss` is `Some`, the KEM secret is mixed into the SAME root KDF as the DH
    /// output, mirroring `dh_ratchet_send` with `pq_ss`.
    fn dh_ratchet_receive(&mut self, new_peer_dh: &PublicKey, pq_ss: Option<&[u8]>) -> Result<()> {
        self.state.recv_message_number = 0;

        // Update peer's DH public key
        self.state.peer_dh_public = Some(new_peer_dh.clone());

        // DH with our current key and their new key
        let our_dh = X25519KeyPair::from_private_bytes(
            self.state
                .my_dh_private
                .as_ref()
                .ok_or(EchoError::ChainExhausted)?
                .0,
        );
        let mut dh_output = our_dh.dh(new_peer_dh)?;

        // Derive new receiving chain (+ PQ secret on an epoch step)
        let (new_root, new_recv_chain) = match pq_ss {
            Some(ss) => kdf::kdf_root_combined(&self.state.root_key, &dh_output, ss),
            None => kdf::kdf_root(&self.state.root_key, &dh_output),
        };
        dh_output.zeroize(); // M2: zeroize DH shared secret
        self.state.root_key = new_root;
        self.state.receiving_chain_key = Some(new_recv_chain);

        // Clear the sending chain: our next send will DH-ratchet from this shared root.
        self.state.sending_chain_key = None;

        // Rotate the receiving header key (the sending side rotates on its own send).
        self.state.receiving_header_key = self.state.next_receiving_header_key.take();
        self.state.next_receiving_header_key =
            Some(kdf::derive_header_key(&self.state.root_key, false));

        self.state.dh_ratchet_number += 1;

        Ok(())
    }

    /// Initiate a PQ epoch ratchet on send (Layer 3), folded into a single DH ratchet step
    /// so the KEM secret reaches the chain keys at a root both parties share. Requires
    /// `peer_epoch_pk` (the caller checks this before invoking). Returns the KEM ciphertext
    /// and our fresh epoch public key to attach to the outgoing header.
    fn dh_ratchet_send_epoch(&mut self) -> Result<(PqCiphertext, PqPublicKey)> {
        let peer_pk = self
            .state
            .peer_epoch_pk
            .as_ref()
            .ok_or(EchoError::PqKemError("no peer PQ key".into()))?;
        let (ct, mut ss) = pq_kem::pq_encapsulate(peer_pk)?;

        let peer_dh = self
            .state
            .peer_dh_public
            .clone()
            .ok_or(EchoError::ChainExhausted)?;
        // Combined DH + PQ root step (kdf_root_combined inside dh_ratchet_send).
        self.dh_ratchet_send(&peer_dh, Some(&ss))?;
        ss.zeroize(); // M4: zeroize PQ shared secret

        // Fresh epoch keypair for the next epoch; advance + reset epoch bookkeeping.
        let (new_pk, new_sk) = pq_kem::pq_keygen();
        let pk_clone = new_pk.clone();
        self.state.my_epoch_pk = Some(new_pk);
        self.state.my_epoch_sk = Some(new_sk);
        self.state.epoch_number += 1;
        self.state.epoch_message_count = 0;
        self.state.epoch_start_time = now_secs();

        Ok((ct, pk_clone))
    }

    /// Skip message keys for out-of-order delivery.
    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        let to_skip = until - self.state.recv_message_number;
        if to_skip > MAX_SKIP {
            return Err(EchoError::TooManySkipped(to_skip, MAX_SKIP));
        }

        let chain_key = self
            .state
            .receiving_chain_key
            .as_ref()
            .ok_or(EchoError::ChainExhausted)?;

        let mut ck = chain_key.clone();
        for i in self.state.recv_message_number..until {
            let (new_ck, mk) = kdf::kdf_chain(&ck);
            self.state
                .skipped_keys
                .insert((self.state.dh_ratchet_number, i), mk);
            ck = new_ck;
        }
        self.state.receiving_chain_key = Some(ck);
        self.state.recv_message_number = until;

        // Cleanup if too many
        self.state.cleanup_skipped_keys();

        Ok(())
    }

    /// Export state for persistence.
    pub fn export_state(&self) -> &RatchetState {
        &self.state
    }
}
