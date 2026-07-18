//! FFI API for flutter_rust_bridge v2.
//!
//! Stateless wrapper functions — all state crosses the boundary as JSON strings.
//! flutter_rust_bridge auto-generates Dart bindings from these functions.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::ed25519::Ed25519KeyPair;
use crate::crypto::kdf;
use crate::crypto::pq_kem;
use crate::crypto::x25519::X25519KeyPair;
use crate::ratchet::session::{EncryptedMessage, TripleRatchetSession};
use crate::ratchet::state::RatchetState;
use crate::ratchet::x4dh::X4DH;
use crate::sealed_sender::{self, SenderCertificate};
use crate::types::*;

// ─── Return types ───

/// Identity key material returned from key generation.
pub struct FfiIdentityKeys {
    /// Ed25519 signing public key (32 bytes, hex)
    pub ed_public: Vec<u8>,
    /// Ed25519 signing private key (32 bytes)
    pub ed_private: Vec<u8>,
    /// X25519 DH public key (32 bytes)
    pub dh_public: Vec<u8>,
    /// X25519 DH private key (32 bytes)
    pub dh_private: Vec<u8>,
    /// Signed prekey public (32 bytes)
    pub spk_public: Vec<u8>,
    /// Signed prekey private (32 bytes)
    pub spk_private: Vec<u8>,
    /// Signature over signed prekey (64 bytes)
    pub spk_signature: Vec<u8>,
    /// PQ public key (1568 bytes)
    pub pq_public: Vec<u8>,
    /// PQ secret key (3168 bytes)
    pub pq_secret: Vec<u8>,
    /// Signature over PQ public key (64 bytes)
    pub pq_signature: Vec<u8>,
}

/// One-time prekey batch result.
pub struct FfiOtpResult {
    /// List of (key_id, public_key_bytes) pairs
    pub prekeys: Vec<FfiOneTimePrekey>,
    /// Corresponding private keys as (key_id, private_key_bytes)
    pub private_keys: Vec<FfiOneTimePrekey>,
}

pub struct FfiOneTimePrekey {
    pub key_id: u32,
    pub key_data: Vec<u8>,
}

/// Encrypt result: updated state + encrypted message components.
pub struct FfiEncryptResult {
    pub state_json: String,
    pub header_bytes: Vec<u8>,
    pub encrypted_header: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Decrypt result: updated state + plaintext.
pub struct FfiDecryptResult {
    pub state_json: String,
    pub plaintext: Vec<u8>,
    pub sender_epoch: u32,
    pub sender_dh_ratchet: u32,
    pub message_number: u32,
}

/// Sealed envelope result.
pub struct FfiSealResult {
    pub envelope_bytes: Vec<u8>,
}

/// Unseal result.
pub struct FfiUnsealResult {
    pub sender_identity: Vec<u8>,
    pub sender_device_id: Vec<u8>,
    pub expiry: u64,
    pub tr3_ciphertext: Vec<u8>,
}

/// Parsed wire message.
pub struct FfiWireMessage {
    pub is_prekey: bool,
    /// Only present for PreKey messages
    pub sender_identity_key: Option<Vec<u8>>,
    pub sender_identity_dh_key: Option<Vec<u8>>,
    pub ephemeral_public: Option<Vec<u8>>,
    pub pq_ciphertext: Option<Vec<u8>>,
    pub used_one_time_prekey_id: Option<u32>,
    /// Always present
    pub ratchet_header: Vec<u8>,
    pub encrypted_header: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

// ─── API Functions ───

/// Generate a full set of identity keys.
pub fn ffi_generate_identity() -> Result<FfiIdentityKeys, String> {
    let ed = Ed25519KeyPair::generate();
    let dh = X25519KeyPair::generate();
    let spk = X25519KeyPair::generate();

    let spk_sig = ed.sign(&spk.public_key().0);

    let (pq_pk, pq_sk) = pq_kem::pq_keygen();
    let pq_sig = ed.sign(&pq_pk.0);

    Ok(FfiIdentityKeys {
        ed_public: ed.public_key().0.to_vec(),
        ed_private: ed.private_key_bytes().0.to_vec(),
        dh_public: dh.public_key().0.to_vec(),
        dh_private: dh.private_key_bytes().0.to_vec(),
        spk_public: spk.public_key().0.to_vec(),
        spk_private: spk.private_key_bytes().0.to_vec(),
        spk_signature: spk_sig,
        pq_public: pq_pk.0,
        pq_secret: pq_sk.0.clone(),
        pq_signature: pq_sig,
    })
}

/// Generate a batch of one-time prekeys.
pub fn ffi_generate_one_time_prekeys(
    count: u32,
    start_id: u32,
) -> Result<FfiOtpResult, String> {
    let mut prekeys = Vec::with_capacity(count as usize);
    let mut private_keys = Vec::with_capacity(count as usize);

    for i in 0..count {
        let kp = X25519KeyPair::generate();
        let kid = start_id + i;
        prekeys.push(FfiOneTimePrekey {
            key_id: kid,
            key_data: kp.public_key().0.to_vec(),
        });
        private_keys.push(FfiOneTimePrekey {
            key_id: kid,
            key_data: kp.private_key_bytes().0.to_vec(),
        });
    }

    Ok(FfiOtpResult {
        prekeys,
        private_keys,
    })
}

/// Run X4DH initiation (Alice's side). Returns (x4dh_result_json, state_json).
pub fn ffi_x4dh_initiate(
    ed_private: Vec<u8>,
    dh_private: Vec<u8>,
    bundle_json: String,
) -> Result<String, String> {
    let ed = ed_keypair_from_bytes(&ed_private)?;
    let dh = dh_keypair_from_bytes(&dh_private)?;
    let bundle: PrekeyBundle =
        serde_json::from_str(&bundle_json).map_err(|e| e.to_string())?;

    let init = X4DH::initiate(&ed, &dh, &bundle).map_err(|e| e.to_string())?;

    // Serialize the init result as JSON
    #[derive(serde::Serialize)]
    struct InitOut {
        root_key: Vec<u8>,
        chain_key: Vec<u8>,
        ephemeral_public: Vec<u8>,
        identity_dh_public: Vec<u8>,
        pq_ciphertext: Vec<u8>,
        used_one_time_prekey_id: Option<u32>,
    }

    let out = InitOut {
        root_key: init.root_key.0.to_vec(),
        chain_key: init.chain_key.0.to_vec(),
        ephemeral_public: init.ephemeral_public.0.to_vec(),
        identity_dh_public: init.identity_dh_public.0.to_vec(),
        pq_ciphertext: init.pq_ciphertext.0,
        used_one_time_prekey_id: init.used_one_time_prekey_id,
    };

    serde_json::to_string(&out).map_err(|e| e.to_string())
}

/// Run X4DH response (Bob's side). Returns x4dh_result_json.
pub fn ffi_x4dh_respond(
    ed_private: Vec<u8>,
    dh_private: Vec<u8>,
    spk_private: Vec<u8>,
    otp_private: Option<Vec<u8>>,
    pq_secret_key: Vec<u8>,
    their_identity_dh: Vec<u8>,
    their_ephemeral: Vec<u8>,
    pq_ciphertext: Vec<u8>,
) -> Result<String, String> {
    let ed = ed_keypair_from_bytes(&ed_private)?;
    let dh = dh_keypair_from_bytes(&dh_private)?;
    let spk = dh_keypair_from_bytes(&spk_private)?;
    let otp = otp_private
        .map(|b| dh_keypair_from_bytes(&b))
        .transpose()?;

    let their_dh = pub_key_from_bytes(&their_identity_dh)?;
    let their_eph = pub_key_from_bytes(&their_ephemeral)?;

    let result = X4DH::respond(
        &ed,
        &dh,
        &spk,
        otp.as_ref(),
        &PqSecretKey(pq_secret_key),
        &their_dh,
        None, // C4: caller should provide Alice's Ed25519 key
        None, // C4: caller should provide DH key signature
        None, // C4: caller should provide Alice's ML-DSA identity
        None, // C4: caller should provide ML-DSA DH key signature
        &their_eph,
        &PqCiphertext(pq_ciphertext),
    )
    .map_err(|e| e.to_string())?;

    #[derive(serde::Serialize)]
    struct RespOut {
        root_key: Vec<u8>,
        chain_key: Vec<u8>,
    }

    let out = RespOut {
        root_key: result.root_key.0.to_vec(),
        chain_key: result.chain_key.0.to_vec(),
    };

    serde_json::to_string(&out).map_err(|e| e.to_string())
}

/// Encrypt a message. Returns updated state + encrypted components.
pub fn ffi_ratchet_encrypt(
    state_json: String,
    plaintext: Vec<u8>,
) -> Result<FfiEncryptResult, String> {
    let state: RatchetState =
        serde_json::from_str(&state_json).map_err(|e| e.to_string())?;
    let mut session = TripleRatchetSession::new(state);

    let enc = session.encrypt(&plaintext).map_err(|e| e.to_string())?;

    let header_bytes =
        bincode::serialize(&enc.header).map_err(|e| e.to_string())?;

    let new_state_json =
        serde_json::to_string(session.export_state()).map_err(|e| e.to_string())?;

    Ok(FfiEncryptResult {
        state_json: new_state_json,
        header_bytes,
        encrypted_header: enc.encrypted_header,
        ciphertext: enc.ciphertext,
    })
}

/// Decrypt a message. Returns updated state + plaintext.
pub fn ffi_ratchet_decrypt(
    state_json: String,
    header_bytes: Vec<u8>,
    encrypted_header: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<FfiDecryptResult, String> {
    let state: RatchetState =
        serde_json::from_str(&state_json).map_err(|e| e.to_string())?;
    let mut session = TripleRatchetSession::new(state);

    let header: MessageHeader =
        bincode::deserialize(&header_bytes).map_err(|e| e.to_string())?;

    let enc_msg = EncryptedMessage {
        header,
        encrypted_header,
        ciphertext,
    };

    let dec = session.decrypt(&enc_msg).map_err(|e| e.to_string())?;

    let new_state_json =
        serde_json::to_string(session.export_state()).map_err(|e| e.to_string())?;

    Ok(FfiDecryptResult {
        state_json: new_state_json,
        plaintext: dec.plaintext,
        sender_epoch: dec.sender_epoch,
        sender_dh_ratchet: dec.sender_dh_ratchet,
        message_number: dec.message_number,
    })
}

/// Seal a message with sealed sender.
pub fn ffi_seal_message(
    recipient_dh_public: Vec<u8>,
    sender_identity: Vec<u8>,
    sender_device_id: Vec<u8>,
    expiry: u64,
    payload: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let recip_dh = pub_key_from_bytes(&recipient_dh_public)?;
    let mut ik = [0u8; 32];
    ik.copy_from_slice(
        sender_identity
            .get(..32)
            .ok_or("sender_identity must be 32 bytes")?,
    );
    let mut did = [0u8; 16];
    did.copy_from_slice(
        sender_device_id
            .get(..16)
            .ok_or("sender_device_id must be 16 bytes")?,
    );

    let cert = SenderCertificate {
        sender_identity: IdentityPublicKey(ik),
        sender_device_id: DeviceId(did),
        expiry,
        server_signature: vec![0u8; 64], // POC placeholder
        sender_signature: vec![0u8; 64], // POC placeholder (no Ed25519 key available in FFI)
    };

    let envelope =
        sealed_sender::seal_message(&recip_dh, &cert, &payload).map_err(|e| e.to_string())?;

    bincode::serialize(&envelope).map_err(|e| e.to_string())
}

/// Unseal a sealed sender envelope. Server pubkey is required for cert verification (H1).
pub fn ffi_unseal_message(
    dh_private: Vec<u8>,
    envelope_bytes: Vec<u8>,
    server_pubkey: Vec<u8>,
) -> Result<FfiUnsealResult, String> {
    let dh = dh_keypair_from_bytes(&dh_private)?;
    let envelope: SealedEnvelope =
        bincode::deserialize(&envelope_bytes).map_err(|e| e.to_string())?;

    let mut spk = [0u8; 32];
    spk.copy_from_slice(
        server_pubkey.get(..32).ok_or("server_pubkey must be 32 bytes")?,
    );

    let (cert, tr3_ciphertext) =
        sealed_sender::unseal_message(&dh, &envelope, &spk).map_err(|e| e.to_string())?;

    Ok(FfiUnsealResult {
        sender_identity: cert.sender_identity.0.to_vec(),
        sender_device_id: cert.sender_device_id.0.to_vec(),
        expiry: cert.expiry,
        tr3_ciphertext,
    })
}

/// Build initiator ratchet state from X4DH result + bundle.
pub fn ffi_build_initiator_state(
    ed_public: Vec<u8>,
    bundle_json: String,
    init_json: String,
) -> Result<String, String> {
    let our_identity = id_pub_from_bytes(&ed_public)?;

    let bundle: PrekeyBundle =
        serde_json::from_str(&bundle_json).map_err(|e| e.to_string())?;

    #[derive(serde::Deserialize)]
    struct InitIn {
        root_key: Vec<u8>,
        chain_key: Vec<u8>,
    }
    let init: InitIn =
        serde_json::from_str(&init_json).map_err(|e| e.to_string())?;

    let (pq_pk, pq_sk) = pq_kem::pq_keygen();
    let new_dh = X25519KeyPair::generate();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut root_key = [0u8; 32];
    root_key.copy_from_slice(
        init.root_key.get(..32).ok_or("root_key must be 32 bytes")?,
    );
    let mut chain_key = [0u8; 32];
    chain_key.copy_from_slice(
        init.chain_key
            .get(..32)
            .ok_or("chain_key must be 32 bytes")?,
    );

    let state = RatchetState {
        local_identity: our_identity,
        remote_identity: bundle.identity_key,
        epoch_number: 0,
        my_epoch_pk: Some(pq_pk),
        my_epoch_sk: Some(pq_sk),
        peer_epoch_pk: Some(bundle.pq_prekey),
        epoch_message_count: 0,
        epoch_start_time: now,
        pending_epoch: None,
        dh_ratchet_number: 0,
        my_dh_public: new_dh.public_key(),
        my_dh_private: Some(new_dh.private_key_bytes()),
        peer_dh_public: Some(bundle.signed_prekey),
        root_key: RootKey(root_key),
        sending_chain_key: Some(ChainKey(chain_key)),
        receiving_chain_key: None,
        send_message_number: 0,
        recv_message_number: 0,
        prev_sending_chain_length: 0,
        // M11: Derive initial header keys (initiator direction)
        sending_header_key: Some(kdf::derive_header_key(&RootKey(root_key), true)),
        receiving_header_key: Some(kdf::derive_header_key(&RootKey(root_key), false)),
        next_sending_header_key: Some(kdf::derive_header_key(&RootKey(root_key), true)),
        next_receiving_header_key: Some(kdf::derive_header_key(&RootKey(root_key), false)),
        skipped_keys: HashMap::new(),
        processed_ids: HashSet::new(),
        processed_order: VecDeque::new(),
    };

    serde_json::to_string(&state).map_err(|e| e.to_string())
}

/// Build responder ratchet state from X4DH response.
pub fn ffi_build_responder_state(
    ed_public: Vec<u8>,
    spk_public: Vec<u8>,
    spk_private: Vec<u8>,
    remote_identity: Vec<u8>,
    peer_dh_public: Vec<u8>,
    x4dh_json: String,
) -> Result<String, String> {
    let our_identity = id_pub_from_bytes(&ed_public)?;
    let remote_id = id_pub_from_bytes(&remote_identity)?;
    let spk = dh_keypair_from_bytes(&spk_private)?;
    let peer_dh = pub_key_from_bytes(&peer_dh_public)?;

    #[derive(serde::Deserialize)]
    struct RespIn {
        root_key: Vec<u8>,
        chain_key: Vec<u8>,
    }
    let resp: RespIn =
        serde_json::from_str(&x4dh_json).map_err(|e| e.to_string())?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut root_key = [0u8; 32];
    root_key.copy_from_slice(
        resp.root_key.get(..32).ok_or("root_key must be 32 bytes")?,
    );
    let mut chain_key = [0u8; 32];
    chain_key.copy_from_slice(
        resp.chain_key
            .get(..32)
            .ok_or("chain_key must be 32 bytes")?,
    );

    let state = RatchetState {
        local_identity: our_identity,
        remote_identity: remote_id,
        epoch_number: 0,
        // BUG #2 (Jun 27): like the Tauri poller, the responder's initial epoch keypair must
        // be its X4DH PQ prekey (the key the initiator encapsulates its first epoch ratchet
        // to). This FFI builder doesn't currently receive the PQ keypair — when the Flutter
        // client is revived, add pq_public/pq_secret params and set these to that pair, or
        // the first epoch ratchet (100-msg / 24h) will silently drop. See OPUS48 notes.
        my_epoch_pk: None,
        my_epoch_sk: None,
        peer_epoch_pk: None,
        epoch_message_count: 0,
        epoch_start_time: now,
        pending_epoch: None,
        dh_ratchet_number: 0,
        my_dh_public: PublicKey(bytes32_from_slice(&spk_public)?),
        my_dh_private: Some(spk.private_key_bytes()),
        peer_dh_public: Some(peer_dh),
        root_key: RootKey(root_key),
        sending_chain_key: None,
        receiving_chain_key: Some(ChainKey(chain_key)),
        send_message_number: 0,
        recv_message_number: 0,
        prev_sending_chain_length: 0,
        // M11: Derive initial header keys (responder swaps send/recv direction)
        sending_header_key: Some(kdf::derive_header_key(&RootKey(root_key), false)),
        receiving_header_key: Some(kdf::derive_header_key(&RootKey(root_key), true)),
        next_sending_header_key: Some(kdf::derive_header_key(&RootKey(root_key), false)),
        next_receiving_header_key: Some(kdf::derive_header_key(&RootKey(root_key), true)),
        skipped_keys: HashMap::new(),
        processed_ids: HashSet::new(),
        processed_order: VecDeque::new(),
    };

    serde_json::to_string(&state).map_err(|e| e.to_string())
}

/// Build a PreKey wire message (first message in a session).
pub fn ffi_build_prekey_wire_message(
    sender_identity_key: Vec<u8>,
    sender_identity_dh_key: Vec<u8>,
    ephemeral_public: Vec<u8>,
    pq_ciphertext: Vec<u8>,
    used_one_time_prekey_id: Option<u32>,
    header_bytes: Vec<u8>,
    encrypted_header: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>, String> {
    #[derive(serde::Serialize, serde::Deserialize)]
    enum WireMessage {
        PreKey {
            sender_identity_key: Vec<u8>,
            sender_identity_dh_key: Vec<u8>,
            ephemeral_public: Vec<u8>,
            pq_ciphertext: Vec<u8>,
            used_one_time_prekey_id: Option<u32>,
            ratchet_header: Vec<u8>,
            encrypted_header: Vec<u8>,
            ciphertext: Vec<u8>,
        },
        Normal {
            ratchet_header: Vec<u8>,
            encrypted_header: Vec<u8>,
            ciphertext: Vec<u8>,
        },
    }

    let msg = WireMessage::PreKey {
        sender_identity_key,
        sender_identity_dh_key,
        ephemeral_public,
        pq_ciphertext,
        used_one_time_prekey_id,
        ratchet_header: header_bytes,
        encrypted_header,
        ciphertext,
    };

    bincode::serialize(&msg).map_err(|e| e.to_string())
}

/// Build a Normal wire message (subsequent messages).
pub fn ffi_build_normal_wire_message(
    header_bytes: Vec<u8>,
    encrypted_header: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>, String> {
    #[derive(serde::Serialize, serde::Deserialize)]
    enum WireMessage {
        PreKey {
            sender_identity_key: Vec<u8>,
            sender_identity_dh_key: Vec<u8>,
            ephemeral_public: Vec<u8>,
            pq_ciphertext: Vec<u8>,
            used_one_time_prekey_id: Option<u32>,
            ratchet_header: Vec<u8>,
            encrypted_header: Vec<u8>,
            ciphertext: Vec<u8>,
        },
        Normal {
            ratchet_header: Vec<u8>,
            encrypted_header: Vec<u8>,
            ciphertext: Vec<u8>,
        },
    }

    let msg = WireMessage::Normal {
        ratchet_header: header_bytes,
        encrypted_header,
        ciphertext,
    };

    bincode::serialize(&msg).map_err(|e| e.to_string())
}

/// Parse a wire message from bytes.
pub fn ffi_parse_wire_message(data: Vec<u8>) -> Result<FfiWireMessage, String> {
    #[derive(serde::Serialize, serde::Deserialize)]
    enum WireMessage {
        PreKey {
            sender_identity_key: Vec<u8>,
            sender_identity_dh_key: Vec<u8>,
            ephemeral_public: Vec<u8>,
            pq_ciphertext: Vec<u8>,
            used_one_time_prekey_id: Option<u32>,
            ratchet_header: Vec<u8>,
            encrypted_header: Vec<u8>,
            ciphertext: Vec<u8>,
        },
        Normal {
            ratchet_header: Vec<u8>,
            encrypted_header: Vec<u8>,
            ciphertext: Vec<u8>,
        },
    }

    let msg: WireMessage =
        bincode::deserialize(&data).map_err(|e| e.to_string())?;

    match msg {
        WireMessage::PreKey {
            sender_identity_key,
            sender_identity_dh_key,
            ephemeral_public,
            pq_ciphertext,
            used_one_time_prekey_id,
            ratchet_header,
            encrypted_header,
            ciphertext,
        } => Ok(FfiWireMessage {
            is_prekey: true,
            sender_identity_key: Some(sender_identity_key),
            sender_identity_dh_key: Some(sender_identity_dh_key),
            ephemeral_public: Some(ephemeral_public),
            pq_ciphertext: Some(pq_ciphertext),
            used_one_time_prekey_id,
            ratchet_header,
            encrypted_header,
            ciphertext,
        }),
        WireMessage::Normal {
            ratchet_header,
            encrypted_header,
            ciphertext,
        } => Ok(FfiWireMessage {
            is_prekey: false,
            sender_identity_key: None,
            sender_identity_dh_key: None,
            ephemeral_public: None,
            pq_ciphertext: None,
            used_one_time_prekey_id: None,
            ratchet_header,
            encrypted_header,
            ciphertext,
        }),
    }
}

/// SHA-256 hash utility.
pub fn ffi_sha256(data: Vec<u8>) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(&data);
    hash.to_vec()
}

/// Verify a key transparency proof bundle.
///
/// Arguments:
/// - `proof_json`: JSON-serialized `TransparencyProofBundle`
/// - `server_pubkey`: Ed25519 public key of the transparency server (32 bytes)
/// - `expected_identity_key`: Expected Ed25519 identity key from the fetched bundle
/// - `expected_identity_dh_key`: Expected X25519 DH key from the fetched bundle
/// - `last_sth_json`: Optional JSON-serialized `SignedTreeHead` (previous cached STH)
///
/// Returns: New STH as JSON string for caching. Errors if any verification fails.
pub fn ffi_verify_transparency_proof(
    proof_json: String,
    server_pubkey: Vec<u8>,
    expected_identity_key: Vec<u8>,
    expected_identity_dh_key: Vec<u8>,
    last_sth_json: Option<String>,
) -> Result<String, String> {
    use crate::transparency::{
        verify_consistency_proof, verify_inclusion_proof, verify_sth,
        TransparencyProofBundle, SignedTreeHead,
    };

    let bundle: TransparencyProofBundle =
        serde_json::from_str(&proof_json).map_err(|e| format!("invalid proof JSON: {}", e))?;

    let pubkey = id_pub_from_bytes(&server_pubkey)?;

    // 1. Verify STH signature
    verify_sth(&bundle.sth, &pubkey)
        .map_err(|_| "TRANSPARENCY FAILURE: STH signature invalid".to_string())?;

    // 2. Verify leaf matches expected keys
    if bundle.leaf.identity_key != expected_identity_key {
        return Err("TRANSPARENCY FAILURE: identity_key mismatch".into());
    }
    if bundle.leaf.identity_dh_key != expected_identity_dh_key {
        return Err("TRANSPARENCY FAILURE: identity_dh_key mismatch".into());
    }

    // 3. Verify inclusion proof
    let leaf_hash = bundle.leaf.hash();
    verify_inclusion_proof(&leaf_hash, &bundle.inclusion_proof, &bundle.sth.root_hash)
        .map_err(|_| "TRANSPARENCY FAILURE: inclusion proof invalid".to_string())?;

    // 4. Verify consistency with previous STH if provided
    if let (Some(ref last_json), Some(ref consistency)) =
        (&last_sth_json, &bundle.consistency_proof)
    {
        let prev_sth: SignedTreeHead = serde_json::from_str(last_json)
            .map_err(|e| format!("invalid last_sth JSON: {}", e))?;

        verify_consistency_proof(consistency, &prev_sth.root_hash, &bundle.sth.root_hash)
            .map_err(|_| "TRANSPARENCY FAILURE: consistency proof failed".to_string())?;
    }

    // Return new STH for caching
    serde_json::to_string(&bundle.sth).map_err(|e| format!("serialize STH: {}", e))
}

// ─── Internal helpers ───

fn bytes32_from_slice(data: &[u8]) -> Result<[u8; 32], String> {
    if data.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", data.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(data);
    Ok(arr)
}

fn ed_keypair_from_bytes(private: &[u8]) -> Result<Ed25519KeyPair, String> {
    let arr = bytes32_from_slice(private)?;
    Ok(Ed25519KeyPair::from_private_bytes(arr))
}

fn dh_keypair_from_bytes(private: &[u8]) -> Result<X25519KeyPair, String> {
    let arr = bytes32_from_slice(private)?;
    Ok(X25519KeyPair::from_private_bytes(arr))
}

fn pub_key_from_bytes(data: &[u8]) -> Result<PublicKey, String> {
    Ok(PublicKey(bytes32_from_slice(data)?))
}

fn id_pub_from_bytes(data: &[u8]) -> Result<IdentityPublicKey, String> {
    Ok(IdentityPublicKey(bytes32_from_slice(data)?))
}
