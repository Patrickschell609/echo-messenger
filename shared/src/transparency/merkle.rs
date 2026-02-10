//! RFC 6962 Merkle tree computation.
//!
//! Implements the binary Merkle tree construction used by Certificate Transparency,
//! adapted for ECHO's key transparency log.

use sha2::{Digest, Sha256};

/// Hash two child nodes: SHA256(0x01 || left || right).
/// The 0x01 prefix distinguishes internal nodes from leaf hashes (0x00 prefix).
pub fn hash_children(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01]); // RFC 6962 internal node prefix
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Compute the Merkle root from a list of leaf hashes.
/// Uses RFC 6962 recursive split at largest power of 2 < n.
pub fn compute_root(leaf_hashes: &[[u8; 32]]) -> [u8; 32] {
    match leaf_hashes.len() {
        0 => Sha256::digest([]).into(), // empty tree = SHA256("")
        1 => leaf_hashes[0],
        n => {
            let split = largest_power_of_2_less_than(n);
            let left = compute_root(&leaf_hashes[..split]);
            let right = compute_root(&leaf_hashes[split..]);
            hash_children(&left, &right)
        }
    }
}

/// Generate an inclusion proof for the leaf at `index` in a tree of `leaf_hashes`.
/// Returns the sibling hashes needed to reconstruct the root.
pub fn generate_inclusion_proof(
    leaf_hashes: &[[u8; 32]],
    index: u64,
) -> Vec<[u8; 32]> {
    let n = leaf_hashes.len();
    if n <= 1 || index as usize >= n {
        return vec![];
    }
    inclusion_proof_inner(leaf_hashes, index as usize)
}

fn inclusion_proof_inner(hashes: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    let n = hashes.len();
    if n == 1 {
        return vec![];
    }

    let split = largest_power_of_2_less_than(n);
    if index < split {
        let mut proof = inclusion_proof_inner(&hashes[..split], index);
        proof.push(compute_root(&hashes[split..]));
        proof
    } else {
        let mut proof = inclusion_proof_inner(&hashes[split..], index - split);
        proof.push(compute_root(&hashes[..split]));
        proof
    }
}

/// Generate a consistency proof between old_size and new_size.
/// Proves that the first old_size leaves of the new tree produce the same root
/// as the old tree.
pub fn generate_consistency_proof(
    leaf_hashes: &[[u8; 32]],
    old_size: u64,
    new_size: u64,
) -> Vec<[u8; 32]> {
    let old = old_size as usize;
    let new = new_size as usize;

    if old == 0 || old > new || new > leaf_hashes.len() {
        return vec![];
    }
    if old == new {
        return vec![];
    }

    // RFC 6962 consistency proof algorithm
    consistency_proof_inner(leaf_hashes, old, new, true)
}

fn consistency_proof_inner(
    hashes: &[[u8; 32]],
    old_size: usize,
    new_size: usize,
    start: bool,
) -> Vec<[u8; 32]> {
    if old_size == new_size {
        if !start {
            return vec![compute_root(&hashes[..old_size])];
        }
        return vec![];
    }

    let split = largest_power_of_2_less_than(new_size);

    if old_size <= split {
        let mut proof = consistency_proof_inner(&hashes[..split], old_size, split, start);
        proof.push(compute_root(&hashes[split..new_size]));
        proof
    } else {
        let mut proof = consistency_proof_inner(
            &hashes[split..],
            old_size - split,
            new_size - split,
            false,
        );
        proof.push(compute_root(&hashes[..split]));
        proof
    }
}

/// Largest power of 2 strictly less than n.
fn largest_power_of_2_less_than(n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transparency::types::TransparencyLeaf;

    fn make_leaf_hash(i: u8) -> [u8; 32] {
        let leaf = TransparencyLeaf {
            device_id: vec![i; 16],
            identity_key: vec![i; 32],
            identity_dh_key: vec![i; 32],
            signed_prekey: vec![i; 32],
            pq_prekey_hash: vec![i; 32],
            timestamp: 1700000000 + i as u64,
            sequence_id: i as i64,
        };
        leaf.hash()
    }

    #[test]
    fn test_empty_tree() {
        let root = compute_root(&[]);
        let expected: [u8; 32] = sha2::Sha256::digest([]).into();
        assert_eq!(root, expected);
    }

    #[test]
    fn test_single_leaf() {
        let h = make_leaf_hash(1);
        let root = compute_root(&[h]);
        assert_eq!(root, h);
    }

    #[test]
    fn test_two_leaves() {
        let h0 = make_leaf_hash(0);
        let h1 = make_leaf_hash(1);
        let root = compute_root(&[h0, h1]);
        let expected = hash_children(&h0, &h1);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_power_of_2_tree() {
        let hashes: Vec<_> = (0..4).map(make_leaf_hash).collect();
        let root = compute_root(&hashes);

        let left = hash_children(&hashes[0], &hashes[1]);
        let right = hash_children(&hashes[2], &hashes[3]);
        let expected = hash_children(&left, &right);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_non_power_of_2_tree() {
        // 3 leaves: split at 2 (largest power of 2 < 3)
        let hashes: Vec<_> = (0..3).map(make_leaf_hash).collect();
        let root = compute_root(&hashes);

        let left = hash_children(&hashes[0], &hashes[1]);
        let expected = hash_children(&left, &hashes[2]);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_five_leaves() {
        // 5 leaves: split at 4
        let hashes: Vec<_> = (0..5).map(make_leaf_hash).collect();
        let root = compute_root(&hashes);

        let left = compute_root(&hashes[..4]);
        let right = hashes[4]; // single leaf
        let expected = hash_children(&left, &right);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_inclusion_proof_single() {
        let h = make_leaf_hash(0);
        let proof = generate_inclusion_proof(&[h], 0);
        assert!(proof.is_empty());
    }

    #[test]
    fn test_inclusion_proof_two_leaves() {
        let hashes: Vec<_> = (0..2).map(make_leaf_hash).collect();
        let proof = generate_inclusion_proof(&hashes, 0);
        assert_eq!(proof.len(), 1);
        assert_eq!(proof[0], hashes[1]); // sibling is the other leaf
    }

    #[test]
    fn test_inclusion_proof_four_leaves() {
        let hashes: Vec<_> = (0..4).map(make_leaf_hash).collect();

        for i in 0..4 {
            let proof = generate_inclusion_proof(&hashes, i);
            assert!(!proof.is_empty(), "proof for index {} should not be empty", i);
        }
    }

    #[test]
    fn test_consistency_proof_same_size() {
        let hashes: Vec<_> = (0..4).map(make_leaf_hash).collect();
        let proof = generate_consistency_proof(&hashes, 4, 4);
        assert!(proof.is_empty());
    }

    #[test]
    fn test_consistency_proof_growth() {
        let hashes: Vec<_> = (0..4).map(make_leaf_hash).collect();
        let proof = generate_consistency_proof(&hashes, 2, 4);
        assert!(!proof.is_empty());
    }

    #[test]
    fn test_consistency_proof_invalid_sizes() {
        let hashes: Vec<_> = (0..4).map(make_leaf_hash).collect();
        assert!(generate_consistency_proof(&hashes, 0, 4).is_empty());
        assert!(generate_consistency_proof(&hashes, 5, 4).is_empty());
    }

    #[test]
    fn test_hash_children_not_commutative() {
        let a = make_leaf_hash(0);
        let b = make_leaf_hash(1);
        assert_ne!(hash_children(&a, &b), hash_children(&b, &a));
    }
}
