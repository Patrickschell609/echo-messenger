//! Post-quantum digital signatures using ML-DSA-87 (FIPS 204).
//!
//! This is the signature counterpart to the ML-KEM-1024 KEM in [`super::pq_kem`].
//! ML-DSA-87 is the FIPS 204 Level-5 parameter set, matching the Level-5
//! ML-KEM-1024 used for the epoch ratchet.
//!
//! Intended use is HYBRID: an ML-DSA signature is produced and verified
//! ALONGSIDE the existing Ed25519 signature, and a verifier requires BOTH to
//! pass. That keeps classical security identical to today while adding
//! protection against a future quantum adversary that could forge Ed25519 —
//! the "harvest-now, forge-later" gap for long-lived identity bindings
//! (identity keys, transparency tree heads, sender certificates).
//!
//! Sizes (bytes): public key 2592, secret key 4896, signature 4627.

use fips204::ml_dsa_87;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};

use crate::error::{EchoError, Result};

/// ML-DSA-87 public key length (bytes).
pub const PK_LEN: usize = ml_dsa_87::PK_LEN;
/// ML-DSA-87 secret key length (bytes).
pub const SK_LEN: usize = ml_dsa_87::SK_LEN;
/// ML-DSA-87 signature length (bytes).
pub const SIG_LEN: usize = ml_dsa_87::SIG_LEN;

/// Generate a new ML-DSA-87 signing key pair as `(public, secret)` byte vectors.
pub fn pq_sign_keygen() -> (Vec<u8>, Vec<u8>) {
    // try_keygen only fails if the OS RNG does; that is unrecoverable.
    let (pk, sk) = ml_dsa_87::try_keygen().expect("OS RNG failure during ML-DSA keygen");
    (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
}

/// Deterministically derive an ML-DSA-87 key pair from a 32-byte seed (FIPS 204 xi).
/// Used to pair a stable ML-DSA server key to the existing Ed25519 transparency key
/// without introducing a second key file.
pub fn pq_sign_keygen_from_seed(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = ml_dsa_87::KG::keygen_from_seed(seed);
    (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
}

/// Sign `message` with an ML-DSA-87 secret key (empty FIPS 204 context string).
pub fn pq_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let sk_bytes: [u8; SK_LEN] = secret_key
        .try_into()
        .map_err(|_| EchoError::PqSignError("invalid ML-DSA secret key length".into()))?;
    let sk = ml_dsa_87::PrivateKey::try_from_bytes(sk_bytes)
        .map_err(|_| EchoError::PqSignError("invalid ML-DSA secret key".into()))?;
    let sig = sk
        .try_sign(message, &[])
        .map_err(|_| EchoError::PqSignError("ML-DSA signing failed".into()))?;
    Ok(sig.to_vec())
}

/// Verify an ML-DSA-87 signature. Returns `Ok(())` iff the signature is valid.
pub fn pq_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let pk_bytes: [u8; PK_LEN] = public_key
        .try_into()
        .map_err(|_| EchoError::PqSignError("invalid ML-DSA public key length".into()))?;
    let pk = ml_dsa_87::PublicKey::try_from_bytes(pk_bytes)
        .map_err(|_| EchoError::PqSignError("invalid ML-DSA public key".into()))?;
    let sig_bytes: [u8; SIG_LEN] = signature
        .try_into()
        .map_err(|_| EchoError::PqSignError("invalid ML-DSA signature length".into()))?;
    if pk.verify(message, &sig_bytes, &[]) {
        Ok(())
    } else {
        Err(EchoError::PqSignError("ML-DSA signature verification failed".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_roundtrip() {
        let (pk, sk) = pq_sign_keygen();
        let msg = b"echo post-quantum identity binding";
        let sig = pq_sign(&sk, msg).unwrap();
        assert!(pq_verify(&pk, msg, &sig).is_ok());
    }

    #[test]
    fn test_tampered_message_fails() {
        let (pk, sk) = pq_sign_keygen();
        let sig = pq_sign(&sk, b"original").unwrap();
        assert!(pq_verify(&pk, b"tampered", &sig).is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let (_pk1, sk1) = pq_sign_keygen();
        let (pk2, _sk2) = pq_sign_keygen();
        let sig = pq_sign(&sk1, b"msg").unwrap();
        assert!(pq_verify(&pk2, b"msg", &sig).is_err());
    }

    #[test]
    fn test_fips204_wire_sizes() {
        // Lock the FIPS 204 ML-DSA-87 sizes so wire-format changes downstream
        // (certs, transparency, prekey bundles) are made against known lengths.
        let (pk, sk) = pq_sign_keygen();
        assert_eq!(pk.len(), 2592, "public key size");
        assert_eq!(sk.len(), 4896, "secret key size");
        let sig = pq_sign(&sk, b"size check").unwrap();
        assert_eq!(sig.len(), 4627, "signature size");
    }

    #[test]
    fn test_bad_lengths_rejected() {
        let (pk, sk) = pq_sign_keygen();
        let sig = pq_sign(&sk, b"m").unwrap();
        assert!(pq_sign(&[0u8; 10], b"m").is_err());
        assert!(pq_verify(&[0u8; 10], b"m", &sig).is_err());
        assert!(pq_verify(&pk, b"m", &[0u8; 10]).is_err());
    }
}
