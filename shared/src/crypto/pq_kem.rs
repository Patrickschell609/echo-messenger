//! Post-quantum Key Encapsulation Mechanism using ML-KEM-1024 (FIPS 203).
//! This is Layer 3 of the Triple Ratchet - the epoch ratchet.
//!
//! Byte sizes are identical to the round-3 Kyber-1024 this replaced
//! (ek 1568, dk 3168, ct 1568, ss 32), so the wire format is unchanged —
//! but the algorithms are not interoperable: sessions and prekeys created
//! under pqcrypto-kyber must be re-established.

use fips203::ml_kem_1024;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};

use crate::error::{EchoError, Result};
use crate::types::{PqCiphertext, PqPublicKey, PqSecretKey};

/// Generate a new ML-KEM-1024 key pair.
pub fn pq_keygen() -> (PqPublicKey, PqSecretKey) {
    // try_keygen only fails if the OS RNG does; that is unrecoverable.
    let (ek, dk) = ml_kem_1024::KG::try_keygen().expect("OS RNG failure during ML-KEM keygen");
    (
        PqPublicKey(ek.into_bytes().to_vec()),
        PqSecretKey(dk.into_bytes().to_vec()),
    )
}

/// Encapsulate: generate shared secret + ciphertext from public key.
/// Used by the sender to initiate an epoch ratchet.
pub fn pq_encapsulate(public_key: &PqPublicKey) -> Result<(PqCiphertext, Vec<u8>)> {
    let ek_bytes: [u8; ml_kem_1024::EK_LEN] = public_key.0.as_slice().try_into()
        .map_err(|_| EchoError::PqKemError("invalid ML-KEM public key length".into()))?;
    // try_from_bytes performs the FIPS 203 modulus check on the encaps key
    let ek = ml_kem_1024::EncapsKey::try_from_bytes(ek_bytes)
        .map_err(|_| EchoError::PqKemError("invalid ML-KEM public key".into()))?;

    let (ss, ct) = ek.try_encaps()
        .map_err(|_| EchoError::PqKemError("ML-KEM encapsulation failed".into()))?;

    Ok((
        PqCiphertext(ct.into_bytes().to_vec()),
        ss.into_bytes().to_vec(),
    ))
}

/// Decapsulate: recover shared secret from ciphertext + secret key.
/// Used by the receiver to complete the epoch ratchet.
/// Invalid ciphertexts yield an implicit-rejection secret, not an error (FIPS 203).
pub fn pq_decapsulate(ciphertext: &PqCiphertext, secret_key: &PqSecretKey) -> Result<Vec<u8>> {
    let ct_bytes: [u8; ml_kem_1024::CT_LEN] = ciphertext.0.as_slice().try_into()
        .map_err(|_| EchoError::PqKemError("invalid ML-KEM ciphertext length".into()))?;
    let ct = ml_kem_1024::CipherText::try_from_bytes(ct_bytes)
        .map_err(|_| EchoError::PqKemError("invalid ML-KEM ciphertext".into()))?;

    let dk_bytes: [u8; ml_kem_1024::DK_LEN] = secret_key.0.as_slice().try_into()
        .map_err(|_| EchoError::PqKemError("invalid ML-KEM secret key length".into()))?;
    let dk = ml_kem_1024::DecapsKey::try_from_bytes(dk_bytes)
        .map_err(|_| EchoError::PqKemError("invalid ML-KEM secret key".into()))?;

    let ss = dk.try_decaps(&ct)
        .map_err(|_| EchoError::PqKemError("ML-KEM decapsulation failed".into()))?;
    Ok(ss.into_bytes().to_vec())
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

    #[test]
    fn test_fips203_wire_sizes() {
        // Lock the FIPS 203 ML-KEM-1024 sizes; these match the previous
        // Kyber-1024 sizes, so nothing downstream (wire, DB, vault) changes.
        let (pk, sk) = pq_keygen();
        assert_eq!(pk.0.len(), 1568, "encaps key size");
        assert_eq!(sk.0.len(), 3168, "decaps key size");
        let (ct, ss) = pq_encapsulate(&pk).unwrap();
        assert_eq!(ct.0.len(), 1568, "ciphertext size");
        assert_eq!(ss.len(), 32, "shared secret size");
    }

    #[test]
    fn test_bad_lengths_rejected() {
        let (pk, sk) = pq_keygen();
        let (ct, _) = pq_encapsulate(&pk).unwrap();
        assert!(pq_encapsulate(&PqPublicKey(vec![0u8; 100])).is_err());
        assert!(pq_decapsulate(&PqCiphertext(vec![0u8; 100]), &sk).is_err());
        assert!(pq_decapsulate(&ct, &PqSecretKey(vec![0u8; 100])).is_err());
    }
}
