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
        // If we have no sending chain, perform an initial DH ratchet step.
        // This happens when the responder (who only received a chain from X4DH) first sends.
        if self.state.sending_chain_key.is_none() {
            if let Some(ref peer_dh) = self.state.peer_dh_public.clone() {
                self.dh_ratchet_send(peer_dh)?;
            }
        }

        // Check if epoch ratchet is needed (Layer 3)
        let (epoch_ct, new_epoch_pk) = if self.state.needs_epoch_ratchet() {
            let (ct, pk) = self.epoch_ratchet_send()?;
            (Some(ct), Some(pk))
        } else {
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

        // Check for epoch ratchet (Layer 3) with validation
        if let (Some(ref ct), Some(ref new_pk)) =
            (&header.epoch_ciphertext, &header.new_epoch_public)
        {
            if header.epoch_number != self.state.epoch_number + 1 {
                return Err(EchoError::InvalidMessage(
                    format!("unexpected epoch number: got {}, expected {}",
                            header.epoch_number, self.state.epoch_number + 1)
                ));
            }

            // M1 invariant (receive-side enforcement): a well-formed sender always
            // pairs an epoch ratchet with a DH ratchet step (see epoch_ratchet_send
            // line 310-312, the M1 fix). This guarantees the PQ-updated root_key
            // propagates into chain keys via the natural dh_ratchet_receive below.
            //
            // If an incoming message carries an epoch update but the sender's DH
            // public hasn't changed, the sender omitted their M1 step -- the PQ
            // secret would be mixed into root_key in isolation and never reach the
            // chain keys that actually encrypt traffic. Reject rather than silently
            // continue with an un-propagated PQ refresh.
            //
            // NOTE: do NOT try to "fix" this by forcing a dh_ratchet_receive here
            // using the current peer_dh_public. The sender (in the M1-omitted case)
            // hasn't updated THEIR sending chain either, so forcing a DH step on
            // our side would desync chain keys and kill the session. Fail-stop is
            // the correct response.
            let dh_changed = self
                .state
                .peer_dh_public
                .as_ref()
                .map(|pk| pk != &header.dh_public)
                .unwrap_or(true);
            if !dh_changed {
                return Err(EchoError::InvalidMessage(
                    "epoch ratchet received without paired DH change (violates M1 invariant)"
                        .into(),
                ));
            }

            self.epoch_ratchet_receive(ct, new_pk)?;
        }

        // Check if DH ratchet needed (Layer 2)
        let need_dh_ratchet = self
            .state
            .peer_dh_public
            .as_ref()
            .map(|pk| pk != &header.dh_public)
            .unwrap_or(true);

        if need_dh_ratchet {
            // FIX: Store remaining skipped keys from OLD chain before destroying it.
            // header.prev_chain_length tells us how many messages the sender sent
            // in their previous chain, so we can store keys we haven't received yet.
            if header.prev_chain_length > self.state.recv_message_number {
                self.skip_message_keys(header.prev_chain_length)?;
            }
            self.dh_ratchet_receive(&header.dh_public)?;
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

    /// Perform DH ratchet step for sending (Layer 2).
    /// Used when the responder needs to initialize their sending chain.
    fn dh_ratchet_send(&mut self, peer_dh: &PublicKey) -> Result<()> {
        self.state.prev_sending_chain_length = self.state.send_message_number;
        self.state.send_message_number = 0;

        // Generate new DH key pair
        let new_dh = X25519KeyPair::generate();
        let mut dh_output = new_dh.dh(peer_dh)?;

        // Derive sending chain from root key + DH output
        let (new_root, new_send_chain) = kdf::kdf_root(&self.state.root_key, &dh_output);
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

    /// Perform DH ratchet step on receive (Layer 2).
    fn dh_ratchet_receive(&mut self, new_peer_dh: &PublicKey) -> Result<()> {
        // Save previous chain length
        self.state.prev_sending_chain_length = self.state.send_message_number;
        self.state.send_message_number = 0;
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

        // Derive new receiving chain
        let (new_root, new_recv_chain) = kdf::kdf_root(&self.state.root_key, &dh_output);
        dh_output.zeroize(); // M2: zeroize DH shared secret
        self.state.root_key = new_root;
        self.state.receiving_chain_key = Some(new_recv_chain);

        // Generate new DH key pair for sending
        let new_dh = X25519KeyPair::generate();
        let mut dh_output2 = new_dh.dh(new_peer_dh)?;

        // Derive new sending chain
        let (new_root2, new_send_chain) = kdf::kdf_root(&self.state.root_key, &dh_output2);
        dh_output2.zeroize(); // M2: zeroize DH shared secret
        self.state.root_key = new_root2;
        self.state.sending_chain_key = Some(new_send_chain);

        // Update header keys
        self.state.sending_header_key = self.state.next_sending_header_key.take();
        self.state.receiving_header_key = self.state.next_receiving_header_key.take();
        self.state.next_sending_header_key =
            Some(kdf::derive_header_key(&self.state.root_key, true));
        self.state.next_receiving_header_key =
            Some(kdf::derive_header_key(&self.state.root_key, false));

        self.state.my_dh_public = new_dh.public_key();
        self.state.my_dh_private = Some(new_dh.private_key_bytes());
        self.state.dh_ratchet_number += 1;

        Ok(())
    }

    /// Perform PQ epoch ratchet on send (Layer 3).
    fn epoch_ratchet_send(&mut self) -> Result<(PqCiphertext, PqPublicKey)> {
        let peer_pk = self
            .state
            .peer_epoch_pk
            .as_ref()
            .ok_or(EchoError::PqKemError("no peer PQ key".into()))?;

        // Encapsulate to peer's PQ public key
        let (ct, mut ss) = pq_kem::pq_encapsulate(peer_pk)?;

        // Update root key with PQ shared secret
        self.state.root_key = kdf::kdf_epoch(&self.state.root_key, &ss);
        ss.zeroize(); // M4: zeroize PQ shared secret

        // M1: Force DH ratchet to propagate PQ protection to chain keys immediately
        if let Some(peer_dh) = self.state.peer_dh_public.clone() {
            self.dh_ratchet_send(&peer_dh)?;
        }

        // Generate new PQ key pair
        let (new_pk, new_sk) = pq_kem::pq_keygen();
        let pk_clone = new_pk.clone();
        self.state.my_epoch_pk = Some(new_pk);
        self.state.my_epoch_sk = Some(new_sk);
        self.state.epoch_number += 1;
        self.state.epoch_message_count = 0;
        self.state.epoch_start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok((ct, pk_clone))
    }

    /// Process received PQ epoch ratchet (Layer 3).
    fn epoch_ratchet_receive(&mut self, ct: &PqCiphertext, new_peer_pk: &PqPublicKey) -> Result<()> {
        let our_sk = self
            .state
            .my_epoch_sk
            .as_ref()
            .ok_or(EchoError::PqKemError("no local PQ secret key".into()))?;

        // Decapsulate
        let mut ss = pq_kem::pq_decapsulate(ct, our_sk)?;

        // Update root key
        self.state.root_key = kdf::kdf_epoch(&self.state.root_key, &ss);
        ss.zeroize(); // M4: zeroize PQ shared secret

        // Update peer's PQ public key
        self.state.peer_epoch_pk = Some(new_peer_pk.clone());

        // Generate new PQ key pair for next epoch
        let (new_pk, new_sk) = pq_kem::pq_keygen();
        self.state.my_epoch_pk = Some(new_pk);
        self.state.my_epoch_sk = Some(new_sk);
        self.state.epoch_number += 1;
        self.state.epoch_message_count = 0;
        self.state.epoch_start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(())
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
