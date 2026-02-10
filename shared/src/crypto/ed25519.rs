use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

use crate::error::{EchoError, Result};
use crate::types::{IdentityPrivateKey, IdentityPublicKey};

/// Ed25519 key pair for identity and signing operations.
/// Used only for: identity keys, prekey signatures, sender certificates.
/// NOT used for per-message signatures (deniability).
pub struct Ed25519KeyPair {
    signing: SigningKey,
    verifying: VerifyingKey,
}

impl Ed25519KeyPair {
    /// Generate a new random Ed25519 identity key pair.
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    /// Sign a message. Returns 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig = self.signing.sign(message);
        sig.to_bytes().to_vec()
    }

    /// Verify a signature against a public key.
    pub fn verify(public_key: &IdentityPublicKey, message: &[u8], signature: &[u8]) -> Result<()> {
        let verifying = VerifyingKey::from_bytes(&public_key.0)
            .map_err(|_| EchoError::InvalidKey("invalid Ed25519 public key".into()))?;

        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| EchoError::InvalidSignature)?;

        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        verifying
            .verify(message, &sig)
            .map_err(|_| EchoError::InvalidSignature)
    }

    /// Get the public identity key.
    pub fn public_key(&self) -> IdentityPublicKey {
        IdentityPublicKey(self.verifying.to_bytes())
    }

    /// Export private key bytes for secure storage.
    pub fn private_key_bytes(&self) -> IdentityPrivateKey {
        IdentityPrivateKey(self.signing.to_bytes())
    }

    /// Reconstruct from stored private key bytes.
    pub fn from_private_bytes(bytes: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&bytes);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let keypair = Ed25519KeyPair::generate();
        let message = b"ECHO protocol test";

        let sig = keypair.sign(message);
        assert!(Ed25519KeyPair::verify(&keypair.public_key(), message, &sig).is_ok());
    }

    #[test]
    fn test_bad_signature_fails() {
        let keypair = Ed25519KeyPair::generate();
        let message = b"ECHO protocol test";
        let mut sig = keypair.sign(message);
        sig[0] ^= 0xFF; // corrupt

        assert!(Ed25519KeyPair::verify(&keypair.public_key(), message, &sig).is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let keypair1 = Ed25519KeyPair::generate();
        let keypair2 = Ed25519KeyPair::generate();
        let message = b"test";

        let sig = keypair1.sign(message);
        assert!(Ed25519KeyPair::verify(&keypair2.public_key(), message, &sig).is_err());
    }
}
