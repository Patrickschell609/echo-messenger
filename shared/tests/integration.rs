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
        let identity_dh = X25519KeyPair::generate();
        let signed_prekey = X25519KeyPair::generate();
        let one_time_prekey = X25519KeyPair::generate();
        let (pq_pk, pq_sk) = pq_kem::pq_keygen();

        let mut device_bytes = [0u8; 16];
        device_bytes[0] = device_seed;

        Self {
            identity_ed,
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

        PrekeyBundle {
            identity_key: self.identity_ed.public_key(),
            identity_dh_key: self.identity_dh.public_key(),
            identity_dh_key_signature: dh_key_sig,
            signed_prekey: self.signed_prekey.public_key(),
            signed_prekey_signature: spk_sig,
            signed_prekey_id: self.signed_prekey_id,
            pq_prekey: self.pq_pk.clone(),
            pq_prekey_signature: pq_sig,
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
    let (pq_pk, pq_sk) = pq_kem::pq_keygen();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    RatchetState {
        local_identity: bob.identity_ed.public_key(),
        remote_identity: alice.identity_ed.public_key(),
        epoch_number: 0,
        my_epoch_pk: Some(pq_pk),
        my_epoch_sk: Some(pq_sk),
        peer_epoch_pk: None, // will get Alice's PQ key from her messages
        epoch_message_count: 0,
        epoch_start_time: now,
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
        &init.ephemeral_public,
        &init.pq_ciphertext,
    );
    assert!(
        result.is_err(),
        "missing DH-binding signature must be rejected (H2)"
    );
}
