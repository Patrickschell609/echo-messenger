//! End-to-end integration test: Alice → Bob with sealed sender.
//!
//! Proves the full flow:
//! 1. Both parties generate identity + prekeys
//! 2. Bob publishes a prekey bundle
//! 3. Alice runs X4DH with Bob's bundle → session established
//! 4. Alice encrypts via Triple Ratchet
//! 5. Alice seals the envelope (server sees nothing)
//! 6. Bob unseals the envelope
//! 7. Bob completes X4DH from Alice's prekey message → session established
//! 8. Bob decrypts → plaintext recovered
//! 9. Bob replies back to Alice (DH ratchet advances)
//! 10. Multi-message exchange with out-of-order delivery

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use echo_crypto::crypto::ed25519::Ed25519KeyPair;
use echo_crypto::crypto::kdf;
use echo_crypto::crypto::pq_kem;
use echo_crypto::crypto::pq_sign;
use echo_crypto::crypto::x25519::X25519KeyPair;
use echo_crypto::ratchet::session::TripleRatchetSession;
use echo_crypto::ratchet::state::RatchetState;
use echo_crypto::ratchet::x4dh::X4DH;
use echo_crypto::sealed_sender::{self, SenderCertificate};
use echo_crypto::types::*;

/// Test server key for signing sender certificates in tests.
fn test_server_key() -> Ed25519KeyPair {
    // Deterministic test key (seed = 42 repeated)
    Ed25519KeyPair::from_private_bytes([42u8; 32])
}

/// Helper: generate a full prekey bundle for a user.
struct UserKeys {
    identity_ed: Ed25519KeyPair,
    identity_mldsa_pk: Vec<u8>,
    identity_mldsa_sk: Vec<u8>,
    identity_dh: X25519KeyPair,
    signed_prekey: X25519KeyPair,
    signed_prekey_id: u32,
    one_time_prekey: X25519KeyPair,
    one_time_prekey_id: u32,
    pq_pk: PqPublicKey,
    pq_sk: PqSecretKey,
    pq_prekey_id: u32,
    device_id: DeviceId,
}

impl UserKeys {
    fn generate(device_seed: u8) -> Self {
        let identity_ed = Ed25519KeyPair::generate();
        let (identity_mldsa_pk, identity_mldsa_sk) = pq_sign::pq_sign_keygen();
        let identity_dh = X25519KeyPair::generate();
        let signed_prekey = X25519KeyPair::generate();
        let one_time_prekey = X25519KeyPair::generate();
        let (pq_pk, pq_sk) = pq_kem::pq_keygen();

        let mut device_bytes = [0u8; 16];
        device_bytes[0] = device_seed;

        Self {
            identity_ed,
            identity_mldsa_pk,
            identity_mldsa_sk,
            identity_dh,
            signed_prekey,
            signed_prekey_id: 1,
            one_time_prekey,
            one_time_prekey_id: 100,
            pq_pk,
            pq_sk,
            pq_prekey_id: 1,
            device_id: DeviceId(device_bytes),
        }
    }

    /// Build the prekey bundle that gets published to the server.
    fn bundle(&self) -> PrekeyBundle {
        let spk_sig = self.identity_ed.sign(&self.signed_prekey.public_key().0);
        let pq_sig = self.identity_ed.sign(&self.pq_pk.0);

        // C3: Sign identity_dh_key with Ed25519 to bind it
        let mut dh_bind_msg = Vec::new();
        dh_bind_msg.extend_from_slice(b"echo-dh-binding:");
        dh_bind_msg.extend_from_slice(&self.identity_dh.public_key().0);
        let dh_key_sig = self.identity_ed.sign(&dh_bind_msg);

        // Post-quantum (ML-DSA-87) halves over the same messages.
        let spk_ml = pq_sign::pq_sign(&self.identity_mldsa_sk, &self.signed_prekey.public_key().0).unwrap();
        let pq_ml = pq_sign::pq_sign(&self.identity_mldsa_sk, &self.pq_pk.0).unwrap();
        let dh_key_ml = pq_sign::pq_sign(&self.identity_mldsa_sk, &dh_bind_msg).unwrap();

        PrekeyBundle {
            identity_key: self.identity_ed.public_key(),
            ml_dsa_identity_key: self.identity_mldsa_pk.clone(),
            identity_dh_key: self.identity_dh.public_key(),
            identity_dh_key_signature: dh_key_sig,
            identity_dh_key_ml_dsa_signature: dh_key_ml,
            signed_prekey: self.signed_prekey.public_key(),
            signed_prekey_signature: spk_sig,
            signed_prekey_ml_dsa_signature: spk_ml,
            signed_prekey_id: self.signed_prekey_id,
            pq_prekey: self.pq_pk.clone(),
            pq_prekey_signature: pq_sig,
            pq_prekey_ml_dsa_signature: pq_ml,
            pq_prekey_id: self.pq_prekey_id,
            one_time_prekey: Some(self.one_time_prekey.public_key()),
            one_time_prekey_id: Some(self.one_time_prekey_id),
        }
    }

    fn sender_cert(&self) -> SenderCertificate {
        let server_key = test_server_key();
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 86400;

        // Sign with test server key (same as real server flow)
        let mut msg = Vec::new();
        msg.extend_from_slice(&self.device_id.0);
        msg.extend_from_slice(&self.identity_ed.public_key().0);
        msg.extend_from_slice(&expiry.to_le_bytes());
        let server_sig = server_key.sign(&msg);

        let mut cert = SenderCertificate {
            sender_identity: self.identity_ed.public_key(),
            sender_device_id: self.device_id.clone(),
            expiry,
            server_signature: server_sig,
            sender_signature: vec![],
        };
        // Counter-sign with sender's Ed25519 key (C1)
        sealed_sender::countersign_sender_cert(&mut cert, &self.identity_ed.private_key_bytes().0);
        cert
    }
}

/// Build initial RatchetState for the initiator (Alice) after X4DH.
fn alice_initial_state(
    alice: &UserKeys,
    bob: &UserKeys,
    root_key: RootKey,
    chain_key: ChainKey,
) -> RatchetState {
    let (pq_pk, pq_sk) = pq_kem::pq_keygen();
    let dh = X25519KeyPair::generate();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    RatchetState {
        local_identity: alice.identity_ed.public_key(),
        remote_identity: bob.identity_ed.public_key(),
        epoch_number: 0,
        my_epoch_pk: Some(pq_pk),
        my_epoch_sk: Some(pq_sk),
        peer_epoch_pk: Some(bob.pq_pk.clone()),
        epoch_message_count: 0,
        epoch_start_time: now,
        pending_epoch: None,
        dh_ratchet_number: 0,
        my_dh_public: dh.public_key(),
        my_dh_private: Some(dh.private_key_bytes()),
        peer_dh_public: Some(bob.signed_prekey.public_key()),
        root_key: root_key.clone(),
        sending_chain_key: Some(chain_key),
        receiving_chain_key: None,
        send_message_number: 0,
        recv_message_number: 0,
        prev_sending_chain_length: 0,
        // M11: Derive initial header keys (initiator direction)
        sending_header_key: Some(kdf::derive_header_key(&root_key, true)),
        receiving_header_key: Some(kdf::derive_header_key(&root_key, false)),
        next_sending_header_key: Some(kdf::derive_header_key(&root_key, true)),
        next_receiving_header_key: Some(kdf::derive_header_key(&root_key, false)),
        skipped_keys: HashMap::new(),
        processed_ids: HashSet::new(),
        processed_order: VecDeque::new(),
    }
}

/// Build initial RatchetState for the responder (Bob) after X4DH.
fn bob_initial_state(
    bob: &UserKeys,
    alice: &UserKeys,
    alice_dh_public: &PublicKey,
    root_key: RootKey,
    chain_key: ChainKey,
) -> RatchetState {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    RatchetState {
        local_identity: bob.identity_ed.public_key(),
        remote_identity: alice.identity_ed.public_key(),
        epoch_number: 0,
        // Responder's initial epoch keypair MUST be its X4DH PQ prekey — that is the key
        // the initiator encapsulates its first epoch ratchet to (initiator sets
        // peer_epoch_pk = bundle.pq_prekey). A fresh/unrelated keypair (or None, as the
        // production poller currently sets) makes the responder unable to decapsulate the
        // first epoch ratchet at the 100-msg / 24h boundary.
        my_epoch_pk: Some(bob.pq_pk.clone()),
        my_epoch_sk: Some(bob.pq_sk.clone()),
        peer_epoch_pk: None, // learns Alice's epoch key from her first epoch update
        epoch_message_count: 0,
        epoch_start_time: now,
        pending_epoch: None,
        dh_ratchet_number: 0,
        my_dh_public: bob.signed_prekey.public_key(),
        my_dh_private: Some(bob.signed_prekey.private_key_bytes()),
        peer_dh_public: Some(alice_dh_public.clone()),
        root_key: root_key.clone(),
        sending_chain_key: None,
        receiving_chain_key: Some(chain_key),
        send_message_number: 0,
        recv_message_number: 0,
        prev_sending_chain_length: 0,
        // M11: Derive initial header keys (responder swaps send/recv direction)
        sending_header_key: Some(kdf::derive_header_key(&root_key, false)),
        receiving_header_key: Some(kdf::derive_header_key(&root_key, true)),
        next_sending_header_key: Some(kdf::derive_header_key(&root_key, false)),
        next_receiving_header_key: Some(kdf::derive_header_key(&root_key, true)),
        skipped_keys: HashMap::new(),
        processed_ids: HashSet::new(),
        processed_order: VecDeque::new(),
    }
}

// ─────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────

#[test]
fn test_x4dh_session_establishment() {
    let alice = UserKeys::generate(1);
    let bob = UserKeys::generate(2);
    let bob_bundle = bob.bundle();

    // Alice initiates X4DH with Bob's published bundle
    let init = X4DH::initiate(&alice.identity_ed, &alice.identity_dh, &bob_bundle).unwrap();

    // Bob responds to Alice's prekey message
    let resp = X4DH::respond(
        &bob.identity_ed,
        &bob.identity_dh,
        &bob.signed_prekey,
        Some(&bob.one_time_prekey),
        &bob.pq_sk,
        &init.identity_dh_public,
        Some(&alice.identity_ed.public_key()),
        Some(&alice.identity_ed.sign(&[b"echo-dh-binding:", alice.identity_dh.public_key().0.as_slice()].concat())),
        Some(&alice.identity_mldsa_pk),
        Some(&pq_sign::pq_sign(&alice.identity_mldsa_sk, &[b"echo-dh-binding:", alice.identity_dh.public_key().0.as_slice()].concat()).unwrap()),
        &init.ephemeral_public,
        &init.pq_ciphertext,
    )
    .unwrap();

    // Both sides must derive the same root key and chain key
    assert_eq!(init.root_key.0, resp.root_key.0, "root keys must match");
    assert_eq!(init.chain_key.0, resp.chain_key.0, "chain keys must match");
}

#[test]
fn test_x4dh_without_one_time_prekey() {
    let alice = UserKeys::generate(1);
    let bob = UserKeys::generate(2);

    // Bundle without one-time prekey (they ran out on server)
    let mut bundle = bob.bundle();
    bundle.one_time_prekey = None;
    bundle.one_time_prekey_id = None;

    let init = X4DH::initiate(&alice.identity_ed, &alice.identity_dh, &bundle).unwrap();

    let resp = X4DH::respond(
        &bob.identity_ed,
        &bob.identity_dh,
        &bob.signed_prekey,
        None, // no one-time prekey
        &bob.pq_sk,
        &init.identity_dh_public,
        Some(&alice.identity_ed.public_key()),
        Some(&alice.identity_ed.sign(&[b"echo-dh-binding:", alice.identity_dh.public_key().0.as_slice()].concat())),
        Some(&alice.identity_mldsa_pk),
        Some(&pq_sign::pq_sign(&alice.identity_mldsa_sk, &[b"echo-dh-binding:", alice.identity_dh.public_key().0.as_slice()].concat()).unwrap()),
        &init.ephemeral_public,
        &init.pq_ciphertext,
    )
    .unwrap();

    assert_eq!(init.root_key.0, resp.root_key.0);
    assert_eq!(init.chain_key.0, resp.chain_key.0);
}

#[test]
fn test_x4dh_bad_signature_rejected() {
    let alice = UserKeys::generate(1);
    let bob = UserKeys::generate(2);

    let mut bundle = bob.bundle();
    // Corrupt the signed prekey signature
    bundle.signed_prekey_signature[0] ^= 0xFF;

    let result = X4DH::initiate(&alice.identity_ed, &alice.identity_dh, &bundle);
    assert!(result.is_err(), "bad SPK signature must be rejected");
}

#[test]
fn test_triple_ratchet_single_message() {
    let alice = UserKeys::generate(1);
    let bob = UserKeys::generate(2);
    let bob_bundle = bob.bundle();

    // X4DH
    let init = X4DH::initiate(&alice.identity_ed, &alice.identity_dh, &bob_bundle).unwrap();
    let resp = X4DH::respond(
        &bob.identity_ed,
        &bob.identity_dh,
        &bob.signed_prekey,
        Some(&bob.one_time_prekey),
        &bob.pq_sk,
        &init.identity_dh_public,
        Some(&alice.identity_ed.public_key()),
        Some(&alice.identity_ed.sign(&[b"echo-dh-binding:", alice.identity_dh.public_key().0.as_slice()].concat())),
        Some(&alice.identity_mldsa_pk),
        Some(&pq_sign::pq_sign(&alice.identity_mldsa_sk, &[b"echo-dh-binding:", alice.identity_dh.public_key().0.as_slice()].concat()).unwrap()),
        &init.ephemeral_public,
        &init.pq_ciphertext,
    )
    .unwrap();

    // Build session states
    let alice_state = alice_initial_state(&alice, &bob, init.root_key, init.chain_key);
    let bob_state = bob_initial_state(&bob, &alice, &alice_state.my_dh_public, resp.root_key, resp.chain_key);

    let mut alice_session = TripleRatchetSession::new(alice_state);
    let mut bob_session = TripleRatchetSession::new(bob_state);

    // Alice encrypts
    let plaintext = b"hey bob, this is a sealed message through the triple ratchet";
    let encrypted = alice_session.encrypt(plaintext).unwrap();

    // Bob decrypts
    let decrypted = bob_session.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted.plaintext, plaintext.to_vec());
}

#[test]
fn test_triple_ratchet_multiple_messages_one_direction() {
    let alice = UserKeys::generate(1);
    let bob = UserKeys::generate(2);
    let bob_bundle = bob.bundle();

    let init = X4DH::initiate(&alice.identity_ed, &alice.identity_dh, &bob_bundle).unwrap();
    let resp = X4DH::respond(
        &bob.identity_ed,
        &bob.identity_dh,
        &bob.signed_prekey,
        Some(&bob.one_time_prekey),
        &bob.pq_sk,
        &init.identity_dh_public,
        Some(&alice.identity_ed.public_key()),
        Some(&alice.identity_ed.sign(&[b"echo-dh-binding:", alice.identity_dh.public_key().0.as_slice()].concat())),
        Some(&alice.identity_mldsa_pk),
        Some(&pq_sign::pq_sign(&alice.identity_mldsa_sk, &[b"echo-dh-binding:", alice.identity_dh.public_key().0.as_slice()].concat()).unwrap()),
        &init.ephemeral_public,
        &init.pq_ciphertext,
    )
    .unwrap();

    let alice_state = alice_initial_state(&alice, &bob, init.root_key, init.chain_key);
    let bob_state = bob_initial_state(&bob, &alice, &alice_state.my_dh_public, resp.root_key, resp.chain_key);

    let mut alice_session = TripleRatchetSession::new(alice_state);
    let mut bob_session = TripleRatchetSession::new(bob_state);

    // Alice sends 10 messages, Bob decrypts all in order
    for i in 0..10u32 {
        let msg = format!("message number {}", i);
        let encrypted = alice_session.encrypt(msg.as_bytes()).unwrap();
        let decrypted = bob_session.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted.plaintext, msg.as_bytes().to_vec());
        assert_eq!(decrypted.message_number, i);
    }
}

#[test]
fn test_triple_ratchet_bidirectional() {
    let alice = UserKeys::generate(1);
    let bob = UserKeys::generate(2);
    let bob_bundle = bob.bundle();

    let init = X4DH::initiate(&alice.identity_ed, &alice.identity_dh, &bob_bundle).unwrap();
    let resp = X4DH::respond(
        &bob.identity_ed,
        &bob.identity_dh,
        &bob.signed_prekey,
        Some(&bob.one_time_prekey),
        &bob.pq_sk,
        &init.identity_dh_public,
        Some(&alice.identity_ed.public_key()),
        Some(&alice.identity_ed.sign(&[b"echo-dh-binding:", alice.identity_dh.public_key().0.as_slice()].concat())),
        Some(&alice.identity_mldsa_pk),
        Some(&pq_sign::pq_sign(&alice.identity_mldsa_sk, &[b"echo-dh-binding:", alice.identity_dh.public_key().0.as_slice()].concat()).unwrap()),
        &init.ephemeral_public,
        &init.pq_ciphertext,
    )
    .unwrap();

    let alice_state = alice_initial_state(&alice, &bob, init.root_key, init.chain_key);
    let bob_state = bob_initial_state(&bob, &alice, &alice_state.my_dh_public, resp.root_key, resp.chain_key);

    let mut alice_session = TripleRatchetSession::new(alice_state);
    let mut bob_session = TripleRatchetSession::new(bob_state);

    // Alice → Bob
    let enc1 = alice_session.encrypt(b"hello bob").unwrap();
    let dec1 = bob_session.decrypt(&enc1).unwrap();
    assert_eq!(dec1.plaintext, b"hello bob");

    // Bob → Alice (triggers DH ratchet)
    let enc2 = bob_session.encrypt(b"hey alice").unwrap();
    let dec2 = alice_session.decrypt(&enc2).unwrap();
    assert_eq!(dec2.plaintext, b"hey alice");

    // Alice → Bob again (another DH ratchet step)
    let enc3 = alice_session.encrypt(b"whats up").unwrap();
    let dec3 = bob_session.decrypt(&enc3).unwrap();
    assert_eq!(dec3.plaintext, b"whats up");

    // Bob → Alice again
    let enc4 = bob_session.encrypt(b"not much").unwrap();
    let dec4 = alice_session.decrypt(&enc4).unwrap();
    assert_eq!(dec4.plaintext, b"not much");
}

#[test]
fn test_sealed_sender_roundtrip() {
    let alice = UserKeys::generate(1);
    let bob = UserKeys::generate(2);

    let cert = alice.sender_cert();
    let inner_payload = b"encrypted ratchet ciphertext goes here";

    // Alice seals to Bob's identity key
    let envelope = sealed_sender::seal_message(
        &bob.identity_dh.public_key(),
        &cert,
        inner_payload,
    )
    .unwrap();

    // Verify envelope is opaque
    assert_eq!(envelope.version, PROTOCOL_VERSION);
    assert!(!envelope.encrypted_payload.is_empty());

    // Bob unseals
    let (recovered_cert, recovered_payload) =
        sealed_sender::unseal_message(&bob.identity_dh, &envelope, &test_server_key().public_key().0).unwrap();

    assert_eq!(recovered_cert.sender_identity, alice.identity_ed.public_key());
    assert_eq!(recovered_cert.sender_device_id, alice.device_id);
    assert_eq!(recovered_payload, inner_payload);
}

#[test]
fn test_sealed_sender_wrong_recipient_fails() {
    let alice = UserKeys::generate(1);
    let bob = UserKeys::generate(2);
    let eve = UserKeys::generate(3);

    let cert = alice.sender_cert();
    let envelope = sealed_sender::seal_message(
        &bob.identity_dh.public_key(),
        &cert,
        b"secret for bob",
    )
    .unwrap();

    // Eve tries to unseal - must fail
    let result = sealed_sender::unseal_message(&eve.identity_dh, &envelope, &test_server_key().public_key().0);
    assert!(result.is_err(), "wrong recipient must not unseal");
}

#[test]
fn test_full_flow_x4dh_ratchet_sealed_sender() {
    // ─── Full POC flow: everything together ───

    let alice = UserKeys::generate(1);
    let bob = UserKeys::generate(2);
    let bob_bundle = bob.bundle();

    // ── Step 1: X4DH session establishment ──
    let init = X4DH::initiate(&alice.identity_ed, &alice.identity_dh, &bob_bundle).unwrap();
    let resp = X4DH::respond(
        &bob.identity_ed,
        &bob.identity_dh,
        &bob.signed_prekey,
        Some(&bob.one_time_prekey),
        &bob.pq_sk,
        &init.identity_dh_public,
        Some(&alice.identity_ed.public_key()),
        Some(&alice.identity_ed.sign(&[b"echo-dh-binding:", alice.identity_dh.public_key().0.as_slice()].concat())),
        Some(&alice.identity_mldsa_pk),
        Some(&pq_sign::pq_sign(&alice.identity_mldsa_sk, &[b"echo-dh-binding:", alice.identity_dh.public_key().0.as_slice()].concat()).unwrap()),
        &init.ephemeral_public,
        &init.pq_ciphertext,
    )
    .unwrap();

    assert_eq!(init.root_key.0, resp.root_key.0);

    // ── Step 2: Build ratchet sessions ──
    let alice_state = alice_initial_state(&alice, &bob, init.root_key, init.chain_key);
    let alice_dh_pub = alice_state.my_dh_public.clone();
    let bob_state = bob_initial_state(&bob, &alice, &alice_dh_pub, resp.root_key, resp.chain_key);

    let mut alice_session = TripleRatchetSession::new(alice_state);
    let mut bob_session = TripleRatchetSession::new(bob_state);

    // ── Step 3: Alice encrypts with Triple Ratchet ──
    let plaintext = b"the server cannot read this, and doesn't even know who sent it";
    let encrypted = alice_session.encrypt(plaintext).unwrap();

    // Serialize the ENTIRE ratchet output for the sealed envelope.
    // In production, header + encrypted_header + ciphertext all go inside the seal.
    let ratchet_payload = bincode::serialize(&(
        &encrypted.header,
        &encrypted.encrypted_header,
        &encrypted.ciphertext,
    )).unwrap();

    // ── Step 4: Alice seals the envelope (sender anonymity) ──
    let cert = alice.sender_cert();
    let envelope = sealed_sender::seal_message(
        &bob.identity_dh.public_key(),
        &cert,
        &ratchet_payload,
    )
    .unwrap();

    // At this point, the server only sees:
    // - envelope.ephemeral_public (random, unlinkable)
    // - envelope.encrypted_payload (opaque blob)
    // - recipient device_id (from routing, NOT in the envelope)
    // The server has ZERO knowledge of sender identity.

    // ── Step 5: Bob unseals the envelope ──
    let (sender_cert, inner) = sealed_sender::unseal_message(&bob.identity_dh, &envelope, &test_server_key().public_key().0).unwrap();

    // Bob now knows who sent it
    assert_eq!(sender_cert.sender_identity, alice.identity_ed.public_key());
    assert_eq!(sender_cert.sender_device_id, alice.device_id);

    // ── Step 6: Bob decrypts with Triple Ratchet ──
    let (header, encrypted_header, ciphertext): (MessageHeader, Vec<u8>, Vec<u8>) =
        bincode::deserialize(&inner).unwrap();
    let ratchet_msg = echo_crypto::ratchet::session::EncryptedMessage {
        header,
        encrypted_header,
        ciphertext,
    };
    let decrypted = bob_session.decrypt(&ratchet_msg).unwrap();

    assert_eq!(decrypted.plaintext, plaintext.to_vec());

    // ── Step 7: Bob replies (DH ratchet advances) ──
    let reply_text = b"got it, loud and clear";
    let reply_enc = bob_session.encrypt(reply_text).unwrap();
    let reply_dec = alice_session.decrypt(&reply_enc).unwrap();
    assert_eq!(reply_dec.plaintext, reply_text.to_vec());

    // ── Step 8: Continue conversation ──
    for i in 0..5 {
        let msg = format!("alice says {}", i);
        let e = alice_session.encrypt(msg.as_bytes()).unwrap();
        let d = bob_session.decrypt(&e).unwrap();
        assert_eq!(d.plaintext, msg.as_bytes());

        let reply = format!("bob replies {}", i);
        let e2 = bob_session.encrypt(reply.as_bytes()).unwrap();
        let d2 = alice_session.decrypt(&e2).unwrap();
        assert_eq!(d2.plaintext, reply.as_bytes());
    }
}

#[test]
fn test_replay_protection() {
    let alice = UserKeys::generate(1);
    let bob = UserKeys::generate(2);
    let bob_bundle = bob.bundle();

    let init = X4DH::initiate(&alice.identity_ed, &alice.identity_dh, &bob_bundle).unwrap();
    let resp = X4DH::respond(
        &bob.identity_ed,
        &bob.identity_dh,
        &bob.signed_prekey,
        Some(&bob.one_time_prekey),
        &bob.pq_sk,
        &init.identity_dh_public,
        Some(&alice.identity_ed.public_key()),
        Some(&alice.identity_ed.sign(&[b"echo-dh-binding:", alice.identity_dh.public_key().0.as_slice()].concat())),
        Some(&alice.identity_mldsa_pk),
        Some(&pq_sign::pq_sign(&alice.identity_mldsa_sk, &[b"echo-dh-binding:", alice.identity_dh.public_key().0.as_slice()].concat()).unwrap()),
        &init.ephemeral_public,
        &init.pq_ciphertext,
    )
    .unwrap();

    let alice_state = alice_initial_state(&alice, &bob, init.root_key, init.chain_key);
    let bob_state = bob_initial_state(&bob, &alice, &alice_state.my_dh_public, resp.root_key, resp.chain_key);

    let mut alice_session = TripleRatchetSession::new(alice_state);
    let mut bob_session = TripleRatchetSession::new(bob_state);

    let encrypted = alice_session.encrypt(b"one time only").unwrap();

    // First decrypt succeeds
    let dec = bob_session.decrypt(&encrypted).unwrap();
    assert_eq!(dec.plaintext, b"one time only");

    // Replay must fail
    let replay = bob_session.decrypt(&encrypted);
    assert!(replay.is_err(), "replay must be rejected");
}

#[test]
fn test_pq_kem_roundtrip() {
    let (pk, sk) = pq_kem::pq_keygen();
    let (ct, ss_sender) = pq_kem::pq_encapsulate(&pk).unwrap();
    let ss_receiver = pq_kem::pq_decapsulate(&ct, &sk).unwrap();
    assert_eq!(ss_sender, ss_receiver, "PQ KEM shared secrets must match");
}

#[test]
fn test_padding_constant_size() {
    use echo_crypto::crypto::aead::{pad_message, unpad_message};

    // Different message sizes should pad to predictable blocks
    let short = pad_message(b"hi");
    let medium = pad_message(b"this is a medium length message for testing");
    let long_msg = vec![0x41u8; 255];
    let long = pad_message(&long_msg);

    // All ≤256 bytes should pad to 256
    assert_eq!(short.len(), PADDING_BLOCK_SIZE);
    assert_eq!(medium.len(), PADDING_BLOCK_SIZE);
    assert_eq!(long.len(), PADDING_BLOCK_SIZE);

    // Roundtrip
    assert_eq!(unpad_message(&short).unwrap(), b"hi");
    assert_eq!(
        unpad_message(&medium).unwrap(),
        b"this is a medium length message for testing"
    );
    assert_eq!(unpad_message(&long).unwrap(), long_msg);
}

// --- Apr 21 audit hardening: identity-binding bypass regression tests ---

/// H2 (initiator): an empty `identity_dh_key_signature` in the prekey bundle must be
/// rejected, not silently skipped. A compromised server could otherwise strip the
/// signature to defeat the C3 identity binding (unknown-key-share).
#[test]
fn test_x4dh_initiate_rejects_empty_dh_binding_sig() {
    let alice = UserKeys::generate(1);
    let bob = UserKeys::generate(2);

    let mut bundle = bob.bundle();
    bundle.identity_dh_key_signature = vec![]; // server stripped the binding signature

    let result = X4DH::initiate(&alice.identity_ed, &alice.identity_dh, &bundle);
    assert!(
        result.is_err(),
        "missing identity_dh_key binding signature must be rejected (H2)"
    );
}

/// H1 (responder): a prekey message missing the initiator's Ed25519 identity must be
/// rejected. The old code fell back to all-zeros in the M8 session KDF, binding the
/// session to a well-known constant.
#[test]
fn test_x4dh_respond_rejects_missing_identity_ed() {
    let alice = UserKeys::generate(1);
    let bob = UserKeys::generate(2);
    let bob_bundle = bob.bundle();
    let init = X4DH::initiate(&alice.identity_ed, &alice.identity_dh, &bob_bundle).unwrap();

    let dh_sig =
        alice.identity_ed.sign(&[b"echo-dh-binding:", alice.identity_dh.public_key().0.as_slice()].concat());
    let result = X4DH::respond(
        &bob.identity_ed,
        &bob.identity_dh,
        &bob.signed_prekey,
        Some(&bob.one_time_prekey),
        &bob.pq_sk,
        &init.identity_dh_public,
        None, // no initiator identity — must be rejected, not zero-bound
        Some(&dh_sig),
        None, // ML-DSA args irrelevant — rejected on missing Ed25519 identity first
        None,
        &init.ephemeral_public,
        &init.pq_ciphertext,
    );
    assert!(
        result.is_err(),
        "missing initiator Ed25519 identity must be rejected (H1)"
    );
}

/// H2 (responder): a prekey message with a missing/empty DH-binding signature must be
/// rejected, not silently skipped.
#[test]
fn test_x4dh_respond_rejects_missing_dh_binding_sig() {
    let alice = UserKeys::generate(1);
    let bob = UserKeys::generate(2);
    let bob_bundle = bob.bundle();
    let init = X4DH::initiate(&alice.identity_ed, &alice.identity_dh, &bob_bundle).unwrap();

    let result = X4DH::respond(
        &bob.identity_ed,
        &bob.identity_dh,
        &bob.signed_prekey,
        Some(&bob.one_time_prekey),
        &bob.pq_sk,
        &init.identity_dh_public,
        Some(&alice.identity_ed.public_key()),
        None, // no DH-binding signature — must be rejected
        None, // ML-DSA args irrelevant — rejected on missing Ed25519 DH-binding sig first
        None,
        &init.ephemeral_public,
        &init.pq_ciphertext,
    );
    assert!(
        result.is_err(),
        "missing DH-binding signature must be rejected (H2)"
    );
}

/// The hybrid flip (Phase 2.3): the initiator must reject a bundle whose ML-DSA
/// half is stripped or forged, even though the Ed25519 half is perfectly valid.
#[test]
fn test_initiate_rejects_bad_ml_dsa_half() {
    let alice = UserKeys::generate(1);
    let bob = UserKeys::generate(2);

    // Stripped ML-DSA identity key -> rejected (no silent classical-only downgrade).
    let mut stripped = bob.bundle();
    stripped.ml_dsa_identity_key = Vec::new();
    assert!(
        X4DH::initiate(&alice.identity_ed, &alice.identity_dh, &stripped).is_err(),
        "bundle missing the ML-DSA identity key must be rejected"
    );

    // Forged ML-DSA signed-prekey signature (from an unrelated key) -> rejected,
    // even though the Ed25519 signed-prekey signature is still valid.
    let (_wrong_pk, wrong_sk) = pq_sign::pq_sign_keygen();
    let mut forged = bob.bundle();
    forged.signed_prekey_ml_dsa_signature =
        pq_sign::pq_sign(&wrong_sk, &forged.signed_prekey.0).unwrap();
    assert!(
        X4DH::initiate(&alice.identity_ed, &alice.identity_dh, &forged).is_err(),
        "bundle with a forged ML-DSA signed-prekey signature must be rejected"
    );
}

// ─────────────────────────────────────────────────────────────
// Long-distance / time-passing tests (Jun 27 2026)
//
// Models the field report: "two boxes chat fine for a few messages, then after
// time passes sending stops working." Covers both time-driven mechanisms — the
// 24h sender-cert expiry and the 24h/100-message PQ epoch ratchet — plus high
// volume and out-of-order delivery (network reordering / latency).
// ─────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Build a server-signed + counter-signed sender cert with an explicit expiry, so we
/// can simulate a cert that has aged past its 24h validity window.
fn sender_cert_with_expiry(user: &UserKeys, expiry: u64) -> SenderCertificate {
    let server_key = test_server_key();
    let mut msg = Vec::new();
    msg.extend_from_slice(&user.device_id.0);
    msg.extend_from_slice(&user.identity_ed.public_key().0);
    msg.extend_from_slice(&expiry.to_le_bytes());
    let server_sig = server_key.sign(&msg);

    let mut cert = SenderCertificate {
        sender_identity: user.identity_ed.public_key(),
        sender_device_id: user.device_id.clone(),
        expiry,
        server_signature: server_sig,
        sender_signature: vec![],
    };
    sealed_sender::countersign_sender_cert(&mut cert, &user.identity_ed.private_key_bytes().0);
    cert
}

/// Run X4DH and build a live bidirectional session pair (Alice initiator, Bob responder).
fn establish_pair() -> (TripleRatchetSession, TripleRatchetSession) {
    let alice = UserKeys::generate(1);
    let bob = UserKeys::generate(2);
    let bob_bundle = bob.bundle();

    let init = X4DH::initiate(&alice.identity_ed, &alice.identity_dh, &bob_bundle).unwrap();
    let resp = X4DH::respond(
        &bob.identity_ed,
        &bob.identity_dh,
        &bob.signed_prekey,
        Some(&bob.one_time_prekey),
        &bob.pq_sk,
        &init.identity_dh_public,
        Some(&alice.identity_ed.public_key()),
        Some(&alice.identity_ed.sign(&[b"echo-dh-binding:", alice.identity_dh.public_key().0.as_slice()].concat())),
        Some(&alice.identity_mldsa_pk),
        Some(&pq_sign::pq_sign(&alice.identity_mldsa_sk, &[b"echo-dh-binding:", alice.identity_dh.public_key().0.as_slice()].concat()).unwrap()),
        &init.ephemeral_public,
        &init.pq_ciphertext,
    )
    .unwrap();

    let alice_state = alice_initial_state(&alice, &bob, init.root_key, init.chain_key);
    let bob_state = bob_initial_state(&bob, &alice, &alice_state.my_dh_public, resp.root_key, resp.chain_key);
    (
        TripleRatchetSession::new(alice_state),
        TripleRatchetSession::new(bob_state),
    )
}

/// THE BUG (Jun 27): the server-signed sender cert is issued with a 24h expiry and is
/// only ever saved at registration — the key-rotation path discards the fresh cert the
/// server returns, so there is no refresh. Once the cached cert ages out, the recipient
/// rejects every sealed message (and the poller ACKs + drops it). Messages silently
/// vanish: exactly "after time passes, sending breaks."
#[test]
fn test_expired_sender_cert_is_rejected_on_receive() {
    let alice = UserKeys::generate(1);
    let bob = UserKeys::generate(2);
    let server_pk = test_server_key().public_key().0;
    let payload = b"ratchet ciphertext goes here";

    // Within the 24h window → accepted.
    let fresh = sender_cert_with_expiry(&alice, now_secs() + 3600);
    let env_ok =
        sealed_sender::seal_message(&bob.identity_dh.public_key(), &fresh, payload).unwrap();
    assert!(
        sealed_sender::unseal_message(&bob.identity_dh, &env_ok, &server_pk).is_ok(),
        "a current sender cert must be accepted"
    );

    // Expired one minute ago → rejected. This is the time-based send failure.
    let expired = sender_cert_with_expiry(&alice, now_secs() - 60);
    let env_bad =
        sealed_sender::seal_message(&bob.identity_dh.public_key(), &expired, payload).unwrap();
    assert!(
        sealed_sender::unseal_message(&bob.identity_dh, &env_bad, &server_pk).is_err(),
        "an expired sender cert must be rejected on receive (reproduces the bug)"
    );
}

/// Long-distance endurance: a high-volume bidirectional conversation (240 messages) that
/// crosses the 100-message PQ epoch boundary multiple times. Every message must decrypt.
/// This is the regression test for bug #3 (epoch ratchet root desync after a turn-around):
/// with the eager ratchet it desynced once the epoch fired mid-conversation; the lazy
/// ratchet keeps both sides on a shared root so the folded PQ secret stays in sync.
#[test]
fn test_long_distance_endurance() {
    let (mut alice_session, mut bob_session) = establish_pair();

    let turns = 80;
    let burst = 3;
    let mut delivered = 0usize;

    for turn in 0..turns {
        // Each turn, one side sends a burst; the other receives it in order. The PQ epoch
        // ratchet rides on a single message, so messages within an epoch transition must be
        // delivered in order (see test_out_of_order_within_chain for intra-chain reordering).
        for i in 0..burst {
            let label = format!("t{}-m{}", turn, i);
            let (env, dec) = if turn % 2 == 0 {
                let e = alice_session.encrypt(label.as_bytes()).unwrap();
                let d = bob_session.decrypt(&e).unwrap();
                (e, d)
            } else {
                let e = bob_session.encrypt(label.as_bytes()).unwrap();
                let d = alice_session.decrypt(&e).unwrap();
                (e, d)
            };
            let _ = env;
            assert_eq!(dec.plaintext, label.as_bytes(), "turn {} msg {}", turn, i);
            delivered += 1;
        }
    }

    assert_eq!(delivered, turns * burst);
    // 120 messages per direction, well past the 100-message PQ_RATCHET_INTERVAL, so the
    // count-triggered epoch ratchet must have fired at least once on each side.
    assert!(
        alice_session.export_state().epoch_number > 0
            && bob_session.export_state().epoch_number > 0,
        "expected a PQ epoch ratchet on both sides across {} messages",
        turns * burst
    );
}

/// Out-of-order delivery WITHIN a single sending chain (no epoch crossing): the skipped-
/// message-key machinery must recover. Alice sends a burst with the same DH key; Bob
/// receives them shuffled.
#[test]
fn test_out_of_order_within_chain() {
    let (mut alice_session, mut bob_session) = establish_pair();

    // Prime a normal turn so both have established chains.
    let e = alice_session.encrypt(b"hi").unwrap();
    assert_eq!(bob_session.decrypt(&e).unwrap().plaintext, b"hi");

    // Alice sends a burst of 5 in one chain, delivered out of order.
    let mut envs = Vec::new();
    for i in 0..5 {
        let label = format!("burst-{}", i);
        envs.push((label.clone(), alice_session.encrypt(label.as_bytes()).unwrap()));
    }
    for &idx in &[3usize, 1, 4, 0, 2] {
        let (label, env) = &envs[idx];
        assert_eq!(
            bob_session.decrypt(env).unwrap().plaintext,
            label.as_bytes(),
            "out-of-order idx {}",
            idx
        );
    }
}

/// Simulate a full day elapsing between messages: the PQ epoch ratchet fires on the 24h
/// TIME trigger (not just the message-count trigger). Verifies the time-driven epoch
/// ratchet pairs with a DH step (M1 invariant) and the message still decrypts — i.e. the
/// 24h boundary itself does NOT break the ratchet (so the cert is the remaining culprit).
#[test]
fn test_epoch_ratchet_first_message_minimal() {
    // Minimal probe: Alice's VERY FIRST message is the epoch ratchet (no warmup, no
    // prior DH turn). Isolates the initiator-epoch / responder-receive pairing.
    let (mut alice_session, mut bob_session) = establish_pair();
    let mut s = alice_session.export_state().clone();
    s.epoch_start_time = now_secs() - (PQ_RATCHET_TIME_INTERVAL + 1);
    let mut alice_session = TripleRatchetSession::new(s);

    let enc = alice_session.encrypt(b"first-and-epoch").unwrap();
    assert_eq!(enc.header.message_type, MessageType::PqEpochUpdate);
    let dec = bob_session.decrypt(&enc).unwrap();
    assert_eq!(dec.plaintext, b"first-and-epoch");
}

/// Time-triggered epoch ratchet AFTER a normal turn-around.
/// OPEN BUG (Jun 27, bug #3): FAILS for the same root-desync reason as the endurance
/// test — the epoch ratchet fires while the roots are asymmetric (Bob has replied once).
/// Run with `cargo test -- --ignored` to reproduce. See OPUS48_SESSION_JUN27.md.
#[test]
fn test_epoch_ratchet_after_24h_gap() {
    let (mut alice_session, mut bob_session) = establish_pair();

    // Warm up with normal exchanges.
    let e = alice_session.encrypt(b"morning").unwrap();
    assert_eq!(bob_session.decrypt(&e).unwrap().plaintext, b"morning");
    let e = bob_session.encrypt(b"morning back").unwrap();
    assert_eq!(alice_session.decrypt(&e).unwrap().plaintext, b"morning back");

    let epoch_before = alice_session.export_state().epoch_number;

    // Roll Alice's epoch clock back 24h + 1s to simulate a day passing.
    let mut s = alice_session.export_state().clone();
    s.epoch_start_time = now_secs() - (PQ_RATCHET_TIME_INTERVAL + 1);
    let mut alice_session = TripleRatchetSession::new(s);

    // Alice's next send must trigger a time-based PQ epoch ratchet.
    let enc = alice_session.encrypt(b"next day, still works").unwrap();
    assert_eq!(
        enc.header.message_type,
        MessageType::PqEpochUpdate,
        "a 24h gap must trigger a PQ epoch ratchet"
    );

    // Bob decrypts across the epoch + paired DH change (M1 invariant satisfied).
    let dec = bob_session.decrypt(&enc).unwrap();
    assert_eq!(dec.plaintext, b"next day, still works");
    assert!(
        alice_session.export_state().epoch_number > epoch_before,
        "epoch number must advance after the time-triggered ratchet"
    );

    // And the conversation continues normally afterward.
    let e = bob_session.encrypt(b"glad it works").unwrap();
    assert_eq!(alice_session.decrypt(&e).unwrap().plaintext, b"glad it works");
}

/// One-directional burst of 250 messages crossing the 100-message epoch boundary twice.
/// Regression for bug B (alternation): the same side must NOT epoch-ratchet twice in a
/// row against a peer epoch key the peer has already rotated away. The alternation gate
/// (peer_epoch_pk nulled on use) keeps Alice in epoch 1 until Bob hands her a fresh key,
/// so all 250 decrypt. Bob stays silent, so Alice keeps advertising the epoch (sticky).
#[test]
fn test_one_directional_burst_crosses_epoch() {
    let (mut alice, mut bob) = establish_pair();
    for i in 0..250u32 {
        let label = format!("m{}", i);
        let env = alice.encrypt(label.as_bytes()).unwrap();
        let dec = bob
            .decrypt(&env)
            .unwrap_or_else(|e| panic!("decrypt failed at msg {}: {:?}", i, e));
        assert_eq!(dec.plaintext, label.as_bytes());
    }
    // Exactly one epoch transition (Bob never sent a fresh key back).
    assert_eq!(alice.export_state().epoch_number, 1);
    assert_eq!(bob.export_state().epoch_number, 1);
}

/// Out-of-order delivery ACROSS an epoch transition: a post-epoch message arrives BEFORE
/// the message that first triggered the epoch. Regression for bug A (ordering): because
/// the sender re-stamps the epoch material on every message (sticky), whichever message
/// arrives first drives the transition, and the earlier one is recovered via skipped keys.
#[test]
fn test_epoch_transition_out_of_order() {
    let (mut alice, mut bob) = establish_pair();

    // Drive Alice to the epoch boundary (100 sends) and capture the first 4 messages of the
    // new epoch. Bob receives nothing yet.
    let mut envs = Vec::new();
    for i in 0..104u32 {
        let label = format!("m{}", i);
        let env = alice.encrypt(label.as_bytes()).unwrap();
        if i >= 100 {
            envs.push((label, env)); // messages 100..104 (100 = the epoch trigger)
        }
    }
    assert_eq!(alice.export_state().epoch_number, 1, "epoch should have fired at msg 100");

    // Deliver them out of order: 103, 101, 100, 102. Message 103 (post-epoch) arrives first
    // and must itself drive Bob's transition; 100 (the original trigger) arrives third.
    for &idx in &[3usize, 1, 0, 2] {
        let (label, env) = &envs[idx];
        let dec = bob
            .decrypt(env)
            .unwrap_or_else(|e| panic!("decrypt failed for msg {}: {:?}", 100 + idx, e));
        assert_eq!(dec.plaintext, label.as_bytes(), "msg {}", 100 + idx);
    }
    assert_eq!(bob.export_state().epoch_number, 1);
}
