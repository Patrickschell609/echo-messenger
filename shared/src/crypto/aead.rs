use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;

use crate::error::{EchoError, Result};
use crate::types::PADDING_BLOCK_SIZE;

/// Encrypt with AES-256-GCM. Returns nonce || ciphertext || tag.
pub fn aead_encrypt(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| EchoError::InvalidKey("invalid AES key".into()))?;

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad })
        .map_err(|_| EchoError::DecryptionFailed)?;

    // nonce (12) || ciphertext+tag
    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt AES-256-GCM. Input is nonce || ciphertext || tag.
pub fn aead_decrypt(key: &[u8; 32], data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 + 16 {
        return Err(EchoError::InvalidMessage("ciphertext too short".into()));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| EchoError::InvalidKey("invalid AES key".into()))?;

    let nonce = Nonce::from_slice(&data[..12]);
    let ciphertext = &data[12..];

    cipher
        .decrypt(nonce, aes_gcm::aead::Payload { msg: ciphertext, aad })
        .map_err(|_| EchoError::DecryptionFailed)
}

/// Pad plaintext to fixed block size (traffic analysis resistance).
/// ISO/IEC 7816-4 padding.
pub fn pad_message(plaintext: &[u8]) -> Vec<u8> {
    let padded_len =
        ((plaintext.len() + 1 + PADDING_BLOCK_SIZE - 1) / PADDING_BLOCK_SIZE) * PADDING_BLOCK_SIZE;
    let mut output = Vec::with_capacity(padded_len);
    output.extend_from_slice(plaintext);
    output.push(0x80); // ISO 7816-4 marker
    output.resize(padded_len, 0x00);
    output
}

/// Remove ISO/IEC 7816-4 padding.
pub fn unpad_message(padded: &[u8]) -> Result<Vec<u8>> {
    let pos = padded
        .iter()
        .rposition(|&b| b == 0x80)
        .ok_or_else(|| EchoError::InvalidMessage("invalid padding".into()))?;

    // Verify all bytes after 0x80 are zero
    if padded[pos + 1..].iter().any(|&b| b != 0) {
        return Err(EchoError::InvalidMessage("corrupted padding".into()));
    }

    Ok(padded[..pos].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"Ghost Protocol says hello";
        let aad = b"header";

        let ct = aead_encrypt(&key, plaintext, aad).unwrap();
        let pt = aead_decrypt(&key, &ct, aad).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let ct = aead_encrypt(&key1, b"secret", b"").unwrap();
        assert!(aead_decrypt(&key2, &ct, b"").is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = [1u8; 32];
        let ct = aead_encrypt(&key, b"secret", b"header1").unwrap();
        assert!(aead_decrypt(&key, &ct, b"header2").is_err());
    }

    #[test]
    fn test_padding_roundtrip() {
        let msg = b"hello world";
        let padded = pad_message(msg);
        assert_eq!(padded.len() % PADDING_BLOCK_SIZE, 0);
        let unpadded = unpad_message(&padded).unwrap();
        assert_eq!(unpadded, msg);
    }

    #[test]
    fn test_padding_fixed_size() {
        // Different length messages should pad to same block boundary
        let short = pad_message(b"hi");
        let medium = pad_message(b"hello world, this is a test");
        assert_eq!(short.len(), PADDING_BLOCK_SIZE);
        assert_eq!(medium.len(), PADDING_BLOCK_SIZE);
    }
}
