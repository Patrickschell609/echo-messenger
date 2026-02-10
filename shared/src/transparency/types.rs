//! Key transparency data types.
//!
//! Implements RFC 6962-style Merkle tree structures for ECHO's
//! key transparency system.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A leaf in the transparency log — represents one key upload event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyLeaf {
    /// Device UUID (16 bytes)
    pub device_id: Vec<u8>,
    /// Ed25519 identity public key (32 bytes)
    pub identity_key: Vec<u8>,
    /// X25519 identity DH public key (32 bytes)
    pub identity_dh_key: Vec<u8>,
    /// X25519 signed prekey (32 bytes)
    pub signed_prekey: Vec<u8>,
    /// SHA256 of PQ prekey (32 bytes, avoids bloating tree with 1568-byte keys)
    pub pq_prekey_hash: Vec<u8>,
    /// Unix timestamp of key upload
    pub timestamp: u64,
    /// Monotonic sequence ID from the transparency log table
    pub sequence_id: i64,
}

impl TransparencyLeaf {
    /// Canonical leaf hash per RFC 6962: SHA256(0x00 || leaf_data).
    /// The 0x00 prefix distinguishes leaf hashes from internal node hashes.
    pub fn hash(&self) -> [u8; 32] {
        let data = self.canonical_bytes();
        let mut hasher = Sha256::new();
        hasher.update([0x00]); // RFC 6962 leaf prefix
        hasher.update(&data);
        hasher.finalize().into()
    }

    /// Deterministic byte serialization for hashing.
    /// Fields are concatenated in a fixed order with length prefixes.
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        // Each field: 4-byte LE length + data
        write_field(&mut buf, &self.device_id);
        write_field(&mut buf, &self.identity_key);
        write_field(&mut buf, &self.identity_dh_key);
        write_field(&mut buf, &self.signed_prekey);
        write_field(&mut buf, &self.pq_prekey_hash);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.sequence_id.to_le_bytes());
        buf
    }
}

fn write_field(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
}

/// Server's signed commitment to the current tree state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTreeHead {
    /// Number of leaves in the tree
    pub tree_size: u64,
    /// Merkle root hash (32 bytes)
    pub root_hash: [u8; 32],
    /// Unix timestamp when this STH was created
    pub timestamp: u64,
    /// Ed25519 signature over the signable bytes
    pub signature: Vec<u8>,
}

/// Domain separation prefix for STH signatures.
const STH_DOMAIN: &[u8] = b"ECHO-KT-STH-v1";

impl SignedTreeHead {
    /// Compute the bytes that get signed/verified.
    /// Format: "ECHO-KT-STH-v1" || tree_size (8 LE) || root_hash (32) || timestamp (8 LE)
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(STH_DOMAIN.len() + 8 + 32 + 8);
        buf.extend_from_slice(STH_DOMAIN);
        buf.extend_from_slice(&self.tree_size.to_le_bytes());
        buf.extend_from_slice(&self.root_hash);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf
    }
}

/// Inclusion proof: proves a specific leaf is in the tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Index of the leaf in the tree
    pub leaf_index: u64,
    /// Tree size at time of proof
    pub tree_size: u64,
    /// Sibling hashes along the path to root
    pub proof_hashes: Vec<[u8; 32]>,
}

/// Consistency proof: proves tree at old_size is a prefix of tree at new_size.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyProof {
    pub old_size: u64,
    pub new_size: u64,
    pub proof_hashes: Vec<[u8; 32]>,
}

/// Bundle returned alongside key fetches — zero extra round trips.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyProofBundle {
    /// Current signed tree head
    pub sth: SignedTreeHead,
    /// Proof that the target leaf is in the tree
    pub inclusion_proof: InclusionProof,
    /// The actual leaf data
    pub leaf: TransparencyLeaf,
    /// Optional: proves this tree is consistent with client's last-seen tree
    pub consistency_proof: Option<ConsistencyProof>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_leaf(seq: i64) -> TransparencyLeaf {
        TransparencyLeaf {
            device_id: vec![0u8; 16],
            identity_key: vec![1u8; 32],
            identity_dh_key: vec![2u8; 32],
            signed_prekey: vec![3u8; 32],
            pq_prekey_hash: vec![4u8; 32],
            timestamp: 1700000000,
            sequence_id: seq,
        }
    }

    #[test]
    fn test_leaf_hash_determinism() {
        let leaf = make_leaf(1);
        let h1 = leaf.hash();
        let h2 = leaf.hash();
        assert_eq!(h1, h2, "same leaf must produce same hash");
    }

    #[test]
    fn test_different_leaves_different_hashes() {
        let l1 = make_leaf(1);
        let l2 = make_leaf(2);
        assert_ne!(l1.hash(), l2.hash());
    }

    #[test]
    fn test_leaf_hash_has_prefix() {
        // The hash must incorporate the 0x00 prefix.
        // Verify by computing without prefix and checking it differs.
        let leaf = make_leaf(1);
        let with_prefix = leaf.hash();

        let data = leaf.canonical_bytes();
        let without_prefix: [u8; 32] = Sha256::digest(&data).into();

        assert_ne!(with_prefix, without_prefix);
    }

    #[test]
    fn test_sth_signable_bytes_format() {
        let sth = SignedTreeHead {
            tree_size: 42,
            root_hash: [0xAA; 32],
            timestamp: 1700000000,
            signature: vec![],
        };
        let bytes = sth.signable_bytes();
        assert!(bytes.starts_with(b"ECHO-KT-STH-v1"));
        assert_eq!(bytes.len(), 14 + 8 + 32 + 8); // domain + tree_size + root + ts
    }

    #[test]
    fn test_canonical_serialization_stability() {
        let leaf = make_leaf(1);
        let b1 = leaf.canonical_bytes();
        let b2 = leaf.canonical_bytes();
        assert_eq!(b1, b2);
    }
}
