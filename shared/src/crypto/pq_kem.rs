//! Post-quantum Key Encapsulation Mechanism using ML-KEM-1024 (Kyber).
//! This is Layer 3 of the Triple Ratchet - the epoch ratchet.

use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};

use crate::error::{EchoError, Result};
use crate::types::{PqCiphertext, PqPublicKey, PqSecretKey};

/// Generate a new ML-KEM-1024 key pair.
pub fn pq_keygen() -> (PqPublicKey, PqSecretKey) {
    let (pk, sk) = kyber1024::keypair();
    (
        PqPublicKey(pk.as_bytes().to_vec()),
        PqSecretKey(sk.as_bytes().to_vec()),
    )
}

/// Encapsulate: generate shared secret + ciphertext from public key.
/// Used by the sender to initiate an epoch ratchet.
pub fn pq_encapsulate(public_key: &PqPublicKey) -> Result<(PqCiphertext, Vec<u8>)> {
    let pk = kyber1024::PublicKey::from_bytes(&public_key.0)
        .map_err(|_| EchoError::PqKemError("invalid ML-KEM public key".into()))?;

    let (ss, ct) = kyber1024::encapsulate(&pk);

    Ok((
        PqCiphertext(ct.as_bytes().to_vec()),
        ss.as_bytes().to_vec(),
    ))
}

/// Decapsulate: recover shared secret from ciphertext + secret key.
/// Used by the receiver to complete the epoch ratchet.
pub fn pq_decapsulate(ciphertext: &PqCiphertext, secret_key: &PqSecretKey) -> Result<Vec<u8>> {
    let ct = kyber1024::Ciphertext::from_bytes(&ciphertext.0)
        .map_err(|_| EchoError::PqKemError("invalid ML-KEM ciphertext".into()))?;

    let sk = kyber1024::SecretKey::from_bytes(&secret_key.0)
        .map_err(|_| EchoError::PqKemError("invalid ML-KEM secret key".into()))?;

    let ss = kyber1024::decapsulate(&ct, &sk);
    Ok(ss.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_roundtrip() {
        let (pk, sk) = pq_keygen();
        let (ct, ss_enc) = pq_encapsulate(&pk).unwrap();
        let ss_dec = pq_decapsulate(&ct, &sk).unwrap();
        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn test_wrong_key_fails() {
        let (pk, _sk1) = pq_keygen();
        let (_pk2, sk2) = pq_keygen();
        let (ct, ss_enc) = pq_encapsulate(&pk).unwrap();
        let ss_dec = pq_decapsulate(&ct, &sk2).unwrap();
        // ML-KEM with wrong key produces different shared secret (implicit reject)
        assert_ne!(ss_enc, ss_dec);
    }
}
