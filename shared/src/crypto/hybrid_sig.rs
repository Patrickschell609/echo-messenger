//! Hybrid (PQ/T) signatures: Ed25519 + ML-DSA-87.
//!
//! A hybrid signature is an Ed25519 signature AND an ML-DSA-87 signature over
//! the same message. Verification requires BOTH to pass, so the construction is
//! at least as strong as either primitive: classical security is unchanged
//! (Ed25519 is still required), and a future quantum adversary that can forge
//! Ed25519 still cannot forge the ML-DSA half.
//!
//! Applied uniformly across every signature in the protocol — identity-key
//! ownership, prekey signatures, sender certificates, transparency tree heads,
//! and per-request HTTP/WS auth — for a single, consistent post-quantum posture
//! with no Ed25519-only surface anywhere (matching the ML-KEM-1024 KEM choice).
//! The primary threat it closes is "harvest-now, forge-later" on the long-lived
//! identity bindings; request-auth coverage is for uniformity.

use serde::{Deserialize, Serialize};

use super::ed25519::Ed25519KeyPair;
use super::pq_sign;
use crate::error::{EchoError, Result};
use crate::types::IdentityPublicKey;

/// A hybrid Ed25519 + ML-DSA-87 signature over a single message.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HybridSignature {
    /// Ed25519 signature (64 bytes).
    pub ed25519: Vec<u8>,
    /// ML-DSA-87 signature (4627 bytes).
    pub ml_dsa: Vec<u8>,
}

/// Produce a hybrid signature over `message`.
pub fn hybrid_sign(
    ed25519_private: &[u8; 32],
    ml_dsa_private: &[u8],
    message: &[u8],
) -> Result<HybridSignature> {
    let ed_kp = Ed25519KeyPair::from_private_bytes(*ed25519_private);
    let ed25519 = ed_kp.sign(message);
    let ml_dsa = pq_sign::pq_sign(ml_dsa_private, message)?;
    Ok(HybridSignature { ed25519, ml_dsa })
}

/// Verify a hybrid signature. Succeeds only if BOTH component signatures verify.
pub fn hybrid_verify(
    ed25519_public: &[u8; 32],
    ml_dsa_public: &[u8],
    message: &[u8],
    sig: &HybridSignature,
) -> Result<()> {
    // Ed25519 half — classical security floor.
    Ed25519KeyPair::verify(&IdentityPublicKey(*ed25519_public), message, &sig.ed25519)
        .map_err(|_| EchoError::PqSignError("hybrid: Ed25519 half failed".into()))?;
    // ML-DSA half — post-quantum security.
    pq_sign::pq_verify(ml_dsa_public, message, &sig.ml_dsa)
        .map_err(|_| EchoError::PqSignError("hybrid: ML-DSA half failed".into()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq_sign::{pq_sign, pq_sign_keygen};

    fn keys() -> ([u8; 32], [u8; 32], Vec<u8>, Vec<u8>) {
        let ed = Ed25519KeyPair::generate();
        let (ml_pub, ml_priv) = pq_sign_keygen();
        (ed.private_key_bytes().0, ed.public_key().0, ml_pub, ml_priv)
    }

    #[test]
    fn test_hybrid_roundtrip() {
        let (ed_priv, ed_pub, ml_pub, ml_priv) = keys();
        let sig = hybrid_sign(&ed_priv, &ml_priv, b"identity binding").unwrap();
        assert!(hybrid_verify(&ed_pub, &ml_pub, b"identity binding", &sig).is_ok());
    }

    #[test]
    fn test_tampered_message_fails() {
        let (ed_priv, ed_pub, ml_pub, ml_priv) = keys();
        let sig = hybrid_sign(&ed_priv, &ml_priv, b"orig").unwrap();
        assert!(hybrid_verify(&ed_pub, &ml_pub, b"tampered", &sig).is_err());
    }

    #[test]
    fn test_ml_dsa_half_required() {
        // Valid Ed25519 half, ML-DSA half from an unrelated key -> must fail.
        let (ed_priv, ed_pub, ml_pub, ml_priv) = keys();
        let msg = b"binding";
        let mut sig = hybrid_sign(&ed_priv, &ml_priv, msg).unwrap();
        let (_wrong_pub, wrong_priv) = pq_sign_keygen();
        sig.ml_dsa = pq_sign(&wrong_priv, msg).unwrap();
        assert!(hybrid_verify(&ed_pub, &ml_pub, msg, &sig).is_err());
    }

    #[test]
    fn test_ed25519_half_required() {
        // Valid ML-DSA half, Ed25519 half from an unrelated key -> must fail.
        let (ed_priv, ed_pub, ml_pub, ml_priv) = keys();
        let msg = b"binding";
        let mut sig = hybrid_sign(&ed_priv, &ml_priv, msg).unwrap();
        sig.ed25519 = Ed25519KeyPair::generate().sign(msg);
        assert!(hybrid_verify(&ed_pub, &ml_pub, msg, &sig).is_err());
    }
}
