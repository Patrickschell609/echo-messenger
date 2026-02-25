//! Sealed Sender: hide who is messaging whom from the server.
//!
//! Flow:
//! 1. Alice generates ephemeral X25519 key
//! 2. Alice computes seal_key = HKDF(ECDH(eph_priv, Bob_identity_pub), "sealed-sender")
//! 3. Alice encrypts: sealed = AEAD(seal_key, sender_cert || tr3_ciphertext)
//! 4. Server receives {eph_pub, sealed} with NO sender authentication
//! 5. Bob decrypts with: seal_key = HKDF(ECDH(bob_priv, eph_pub), "sealed-sender")

use crate::crypto::aead;
use crate::crypto::kdf;
use crate::crypto::x25519::X25519KeyPair;
use crate::error::{EchoError, Result};
use crate::types::*;

const SEALED_SENDER_INFO: &[u8] = b"echo-sealed-sender-v1";

/// Sender certificate (included inside sealed envelope).
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SenderCertificate {
    pub sender_identity: IdentityPublicKey,
    pub sender_device_id: DeviceId,
    pub expiry: u64,
    pub server_signature: Vec<u8>, // Server signs to prevent spoofing
    /// Sender counter-signature: Ed25519 sign over (device_id || identity || expiry || server_sig).
    /// Prevents a compromised server from forging certs for arbitrary identities.
    #[serde(default)]
    pub sender_signature: Vec<u8>,
}

/// Verify a sender certificate's server signature AND sender counter-signature.
///
/// The server signs: device_id_bytes || identity_key_bytes || expiry_le_bytes
/// using its Ed25519 transparency key.
///
/// The sender counter-signs: "echo-sender-cert-v1:" || device_id || identity_key || expiry || server_signature
/// using their Ed25519 identity key. This prevents a compromised server from forging certs.
pub fn verify_sender_cert(
    cert: &SenderCertificate,
    server_pubkey: &[u8; 32],
) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    if cert.server_signature.len() != 64 {
        return Err(EchoError::SealedSenderFailed);
    }

    // Check expiry
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now > cert.expiry {
        return Err(EchoError::SealedSenderFailed);
    }

    // --- Verify server signature ---
    // Reconstruct the signed message: device_id || identity_key || expiry
    let mut msg = Vec::new();
    msg.extend_from_slice(&cert.sender_device_id.0);
    msg.extend_from_slice(&cert.sender_identity.0);
    msg.extend_from_slice(&cert.expiry.to_le_bytes());

    let vk = VerifyingKey::from_bytes(server_pubkey)
        .map_err(|_| EchoError::SealedSenderFailed)?;

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&cert.server_signature);
    let sig = Signature::from_bytes(&sig_arr);

    vk.verify(&msg, &sig)
        .map_err(|_| EchoError::SealedSenderFailed)?;

    // --- Verify sender counter-signature (C1: prevents server forgery) ---
    if cert.sender_signature.len() != 64 {
        return Err(EchoError::SealedSenderFailed);
    }

    let mut sender_msg = Vec::new();
    sender_msg.extend_from_slice(b"echo-sender-cert-v1:");
    sender_msg.extend_from_slice(&cert.sender_device_id.0);
    sender_msg.extend_from_slice(&cert.sender_identity.0);
    sender_msg.extend_from_slice(&cert.expiry.to_le_bytes());
    sender_msg.extend_from_slice(&cert.server_signature);

    let sender_vk = VerifyingKey::from_bytes(&cert.sender_identity.0)
        .map_err(|_| EchoError::SealedSenderFailed)?;

    let mut sender_sig_arr = [0u8; 64];
    sender_sig_arr.copy_from_slice(&cert.sender_signature);
    let sender_sig = Signature::from_bytes(&sender_sig_arr);

    sender_vk.verify(&sender_msg, &sender_sig)
        .map_err(|_| EchoError::SealedSenderFailed)?;

    Ok(())
}

/// Counter-sign a server-signed sender certificate with the sender's Ed25519 identity key.
/// Must be called after receiving the cert from the server and before using it.
pub fn countersign_sender_cert(
    cert: &mut SenderCertificate,
    sender_ed25519_private: &[u8; 32],
) {
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::Signer;

    let mut msg = Vec::new();
    msg.extend_from_slice(b"echo-sender-cert-v1:");
    msg.extend_from_slice(&cert.sender_device_id.0);
    msg.extend_from_slice(&cert.sender_identity.0);
    msg.extend_from_slice(&cert.expiry.to_le_bytes());
    msg.extend_from_slice(&cert.server_signature);

    let sk = SigningKey::from_bytes(sender_ed25519_private);
    let sig = sk.sign(&msg);
    cert.sender_signature = sig.to_bytes().to_vec();
}

/// Seal a message (sender side).
/// Returns a SealedEnvelope that the server cannot read.
pub fn seal_message(
    recipient_dh_key: &PublicKey,
    sender_cert: &SenderCertificate,
    tr3_ciphertext: &[u8],
) -> Result<SealedEnvelope> {
    // Generate ephemeral key
    let ephemeral = X25519KeyPair::generate();

    // DH with recipient's X25519 identity DH key
    let dh_output = ephemeral.dh(recipient_dh_key)?;

    // Derive seal key
    let seal_key_bytes = kdf::hkdf_derive(&[0u8; 32], &dh_output, SEALED_SENDER_INFO, 32);
    let mut seal_key = [0u8; 32];
    seal_key.copy_from_slice(&seal_key_bytes);

    // Serialize sender cert + ciphertext
    let cert_bytes = bincode::serialize(sender_cert)
        .map_err(|e| EchoError::SerializationError(e.to_string()))?;

    let mut payload = Vec::new();
    // Length-prefix the certificate
    payload.extend_from_slice(&(cert_bytes.len() as u32).to_le_bytes());
    payload.extend_from_slice(&cert_bytes);
    payload.extend_from_slice(tr3_ciphertext);

    // Encrypt
    let encrypted = aead::aead_encrypt(&seal_key, &payload, b"sealed-sender")?;

    Ok(SealedEnvelope {
        version: PROTOCOL_VERSION,
        ephemeral_public: ephemeral.public_key(),
        encrypted_payload: encrypted,
    })
}

/// Maximum serialized sender certificate size (4 KB — generous for Ed25519 + device ID + expiry).
const MAX_CERT_LEN: usize = 4096;

/// Unseal a message (recipient side).
/// Server pubkey is REQUIRED -- sender certificate signature and expiry are always verified (H1).
/// Returns (sender_certificate, tr3_ciphertext).
pub fn unseal_message(
    our_identity_dh: &X25519KeyPair,
    envelope: &SealedEnvelope,
    server_pubkey: &[u8; 32],
) -> Result<(SenderCertificate, Vec<u8>)> {
    // DH with ephemeral key
    let dh_output = our_identity_dh.dh(&envelope.ephemeral_public)?;

    // Derive seal key (same as sender)
    let seal_key_bytes = kdf::hkdf_derive(&[0u8; 32], &dh_output, SEALED_SENDER_INFO, 32);
    let mut seal_key = [0u8; 32];
    seal_key.copy_from_slice(&seal_key_bytes);

    // Decrypt payload
    let payload = aead::aead_decrypt(&seal_key, &envelope.encrypted_payload, b"sealed-sender")?;

    // Parse: cert_len (4 bytes) || cert || tr3_ciphertext
    if payload.len() < 4 {
        return Err(EchoError::SealedSenderFailed);
    }

    let cert_len = u32::from_le_bytes(
        payload[..4].try_into().map_err(|_| EchoError::SealedSenderFailed)?
    ) as usize;

    // Bounds check: prevent OOM from malicious cert_len
    if cert_len > MAX_CERT_LEN {
        return Err(EchoError::SealedSenderFailed);
    }

    // Bounds check: prevent overflow on 32-bit (use checked_add)
    let cert_end = 4usize.checked_add(cert_len).ok_or(EchoError::SealedSenderFailed)?;
    if payload.len() < cert_end {
        return Err(EchoError::SealedSenderFailed);
    }

    let cert: SenderCertificate = bincode::deserialize(&payload[4..cert_end])
        .map_err(|_| EchoError::SealedSenderFailed)?;

    // Always verify sender cert (H1: server_pubkey is now mandatory)
    verify_sender_cert(&cert, server_pubkey)?;

    let tr3_ciphertext = payload[cert_end..].to_vec();

    Ok((cert, tr3_ciphertext))
}
