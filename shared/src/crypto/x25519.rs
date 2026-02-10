use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public, StaticSecret};
use zeroize::Zeroize;

use crate::error::{EchoError, Result};
use crate::types::{PrivateKey, PublicKey};

/// X25519 key pair for DH ratchet operations.
pub struct X25519KeyPair {
    secret: StaticSecret,
    public: X25519Public,
}

impl X25519KeyPair {
    /// Generate a new random X25519 key pair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519Public::from(&secret);
        Self { secret, public }
    }

    /// Perform Diffie-Hellman key exchange.
    pub fn dh(&self, their_public: &PublicKey) -> Result<[u8; 32]> {
        let their_key = X25519Public::from(their_public.0);
        let shared = self.secret.diffie_hellman(&their_key);

        // Check for zero output (low-order point attack)
        let bytes = shared.to_bytes();
        if bytes.iter().all(|&b| b == 0) {
            return Err(EchoError::InvalidKey("DH produced zero output".into()));
        }

        Ok(bytes)
    }

    /// Get the public key bytes.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.public.to_bytes())
    }

    /// Export the private key bytes (for serialization).
    pub fn private_key_bytes(&self) -> PrivateKey {
        PrivateKey(self.secret.to_bytes())
    }

    /// Reconstruct from raw private key bytes.
    pub fn from_private_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = X25519Public::from(&secret);
        Self { secret, public }
    }
}

impl Drop for X25519KeyPair {
    fn drop(&mut self) {
        // StaticSecret implements Zeroize internally
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dh_exchange() {
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();

        let alice_shared = alice.dh(&bob.public_key()).unwrap();
        let bob_shared = bob.dh(&alice.public_key()).unwrap();

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_keypair_roundtrip() {
        let original = X25519KeyPair::generate();
        let pub_key = original.public_key();
        let priv_bytes = original.private_key_bytes();

        let restored = X25519KeyPair::from_private_bytes(priv_bytes.0);
        assert_eq!(restored.public_key(), pub_key);
    }
}
