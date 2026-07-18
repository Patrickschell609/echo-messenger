//! Client-side verification of transparency proofs.
//!
//! These functions run on the client (CLI and Flutter via FFI) to verify
//! that the server's Merkle tree is consistent and includes the expected keys.

use crate::crypto::ed25519::Ed25519KeyPair;
use crate::error::{EchoError, Result};
use crate::types::IdentityPublicKey;

use super::merkle::hash_children;
use super::types::{ConsistencyProof, InclusionProof, SignedTreeHead};

/// Verify an inclusion proof: that a leaf hash is at the claimed position in the tree.
pub fn verify_inclusion_proof(
    leaf_hash: &[u8; 32],
    proof: &InclusionProof,
    expected_root: &[u8; 32],
) -> Result<()> {
    if proof.tree_size == 0 {
        return Err(EchoError::InvalidMessage("empty tree".into()));
    }

    if proof.leaf_index >= proof.tree_size {
        return Err(EchoError::InvalidMessage("leaf index out of range".into()));
    }

    // Single-leaf tree: no proof hashes needed
    if proof.tree_size == 1 {
        if proof.proof_hashes.is_empty() && leaf_hash == expected_root {
            return Ok(());
        }
        return Err(EchoError::InvalidMessage("inclusion proof failed".into()));
    }

    let mut proof_idx = 0;
    let computed = verify_inclusion_inner(
        leaf_hash,
        proof.leaf_index as usize,
        proof.tree_size as usize,
        &proof.proof_hashes,
        &mut proof_idx,
    )?;

    if proof_idx != proof.proof_hashes.len() {
        return Err(EchoError::InvalidMessage(
            "inclusion proof: extra hashes".into(),
        ));
    }

    if computed == *expected_root {
        Ok(())
    } else {
        Err(EchoError::InvalidMessage(
            "inclusion proof: computed root does not match expected".into(),
        ))
    }
}

/// Recursive verification that mirrors the generation algorithm exactly.
/// The generator recurses into the subtree containing the leaf first,
/// then appends the hash of the other subtree.
/// So the verifier must consume proof hashes in the same order.
fn verify_inclusion_inner(
    leaf_hash: &[u8; 32],
    index: usize,
    tree_size: usize,
    proof_hashes: &[[u8; 32]],
    proof_idx: &mut usize,
) -> Result<[u8; 32]> {
    if tree_size == 1 {
        return Ok(*leaf_hash);
    }

    let split = largest_power_of_2_less_than(tree_size);

    if index < split {
        // Leaf is in the left subtree — recurse left, then combine with right sibling
        let left = verify_inclusion_inner(leaf_hash, index, split, proof_hashes, proof_idx)?;
        if *proof_idx >= proof_hashes.len() {
            return Err(EchoError::InvalidMessage(
                "inclusion proof: not enough hashes".into(),
            ));
        }
        let right = proof_hashes[*proof_idx];
        *proof_idx += 1;
        Ok(hash_children(&left, &right))
    } else {
        // Leaf is in the right subtree — recurse right, then combine with left sibling
        let right = verify_inclusion_inner(
            leaf_hash,
            index - split,
            tree_size - split,
            proof_hashes,
            proof_idx,
        )?;
        if *proof_idx >= proof_hashes.len() {
            return Err(EchoError::InvalidMessage(
                "inclusion proof: not enough hashes".into(),
            ));
        }
        let left = proof_hashes[*proof_idx];
        *proof_idx += 1;
        Ok(hash_children(&left, &right))
    }
}

/// Verify a consistency proof: the old tree is a prefix of the new tree.
///
/// Uses the known old_root as input, then reconstructs the new root
/// from the proof hashes, mirroring the generation algorithm.
pub fn verify_consistency_proof(
    proof: &ConsistencyProof,
    old_root: &[u8; 32],
    new_root: &[u8; 32],
) -> Result<()> {
    if proof.old_size == 0 || proof.old_size > proof.new_size {
        return Err(EchoError::InvalidMessage(
            "consistency proof: invalid sizes".into(),
        ));
    }

    if proof.old_size == proof.new_size {
        if old_root == new_root && proof.proof_hashes.is_empty() {
            return Ok(());
        }
        return Err(EchoError::InvalidMessage(
            "consistency proof: same size but different roots".into(),
        ));
    }

    // Use the generation algorithm structure to verify:
    // We pass the old_root in as the known value for the "start" node,
    // then reconstruct both roots and check they match.
    let mut proof_idx = 0;
    let (computed_old, computed_new) = verify_consistency_inner(
        proof.old_size as usize,
        proof.new_size as usize,
        &proof.proof_hashes,
        &mut proof_idx,
        true,
        old_root,
    )?;

    if proof_idx != proof.proof_hashes.len() {
        return Err(EchoError::InvalidMessage(
            "consistency proof: extra hashes".into(),
        ));
    }

    if computed_old != *old_root {
        return Err(EchoError::InvalidMessage(
            "consistency proof: old root mismatch".into(),
        ));
    }
    if computed_new != *new_root {
        return Err(EchoError::InvalidMessage(
            "consistency proof: new root mismatch".into(),
        ));
    }

    Ok(())
}

/// Mirrors the consistency proof generation algorithm exactly.
/// Returns (old_root, new_root) reconstructed from proof hashes.
///
/// The `known_old_root` parameter is used when start==true and old==new,
/// because the generator doesn't emit a hash for that case — it's the
/// root we already know.
fn verify_consistency_inner(
    old_size: usize,
    new_size: usize,
    proof_hashes: &[[u8; 32]],
    proof_idx: &mut usize,
    start: bool,
    known_old_root: &[u8; 32],
) -> Result<([u8; 32], [u8; 32])> {
    if old_size == new_size {
        if !start {
            // The generation emits compute_root for this range
            if *proof_idx >= proof_hashes.len() {
                return Err(EchoError::InvalidMessage(
                    "consistency proof: not enough hashes".into(),
                ));
            }
            let hash = proof_hashes[*proof_idx];
            *proof_idx += 1;
            return Ok((hash, hash));
        }
        // start==true && old==new: generator emits nothing.
        // This IS the old root — use the known value.
        return Ok((*known_old_root, *known_old_root));
    }

    let split = largest_power_of_2_less_than(new_size);

    if old_size <= split {
        // Recurse into left subtree
        let (old_left, new_left) = verify_consistency_inner(
            old_size, split, proof_hashes, proof_idx, start, known_old_root,
        )?;
        // Right subtree hash
        if *proof_idx >= proof_hashes.len() {
            return Err(EchoError::InvalidMessage(
                "consistency proof: not enough hashes".into(),
            ));
        }
        let right_hash = proof_hashes[*proof_idx];
        *proof_idx += 1;
        Ok((old_left, hash_children(&new_left, &right_hash)))
    } else {
        // Recurse into right subtree (shifted)
        let (old_right, new_right) = verify_consistency_inner(
            old_size - split,
            new_size - split,
            proof_hashes,
            proof_idx,
            false,
            known_old_root,
        )?;
        // Left subtree hash
        if *proof_idx >= proof_hashes.len() {
            return Err(EchoError::InvalidMessage(
                "consistency proof: not enough hashes".into(),
            ));
        }
        let left_hash = proof_hashes[*proof_idx];
        *proof_idx += 1;
        Ok((
            hash_children(&left_hash, &old_right),
            hash_children(&left_hash, &new_right),
        ))
    }
}

/// Verify a Signed Tree Head's hybrid Ed25519 + ML-DSA-87 signature.
/// Both halves are mandatory — no classical-only downgrade.
pub fn verify_sth(
    sth: &SignedTreeHead,
    server_public_key: &IdentityPublicKey,
    server_ml_dsa_pubkey: &[u8],
) -> Result<()> {
    let signable = sth.signable_bytes();
    Ed25519KeyPair::verify(server_public_key, &signable, &sth.signature)?;
    crate::crypto::pq_sign::pq_verify(server_ml_dsa_pubkey, &signable, &sth.ml_dsa_signature)
}

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
    use crate::transparency::merkle::{compute_root, generate_consistency_proof, generate_inclusion_proof};
    use crate::transparency::types::TransparencyLeaf;

    fn make_leaf_hash(i: u8) -> [u8; 32] {
        TransparencyLeaf {
            device_id: vec![i; 16],
            identity_key: vec![i; 32],
            identity_dh_key: vec![i; 32],
            signed_prekey: vec![i; 32],
            pq_prekey_hash: vec![i; 32],
            timestamp: 1700000000 + i as u64,
            sequence_id: i as i64,
        }
        .hash()
    }

    #[test]
    fn test_verify_inclusion_single_leaf() {
        let h = make_leaf_hash(0);
        let root = compute_root(&[h]);
        let proof = InclusionProof {
            leaf_index: 0,
            tree_size: 1,
            proof_hashes: vec![],
        };
        assert!(verify_inclusion_proof(&h, &proof, &root).is_ok());
    }

    #[test]
    fn test_verify_inclusion_two_leaves() {
        let hashes: Vec<_> = (0..2).map(make_leaf_hash).collect();
        let root = compute_root(&hashes);
        let proof_hashes = generate_inclusion_proof(&hashes, 0);

        let proof = InclusionProof {
            leaf_index: 0,
            tree_size: 2,
            proof_hashes,
        };
        assert!(verify_inclusion_proof(&hashes[0], &proof, &root).is_ok());
    }

    #[test]
    fn test_verify_inclusion_four_leaves() {
        let hashes: Vec<_> = (0..4).map(make_leaf_hash).collect();
        let root = compute_root(&hashes);

        for i in 0..4u64 {
            let proof_hashes = generate_inclusion_proof(&hashes, i);
            let proof = InclusionProof {
                leaf_index: i,
                tree_size: 4,
                proof_hashes,
            };
            assert!(
                verify_inclusion_proof(&hashes[i as usize], &proof, &root).is_ok(),
                "inclusion verification failed for index {}",
                i
            );
        }
    }

    #[test]
    fn test_verify_inclusion_seven_leaves() {
        let hashes: Vec<_> = (0..7).map(make_leaf_hash).collect();
        let root = compute_root(&hashes);

        for i in 0..7u64 {
            let proof_hashes = generate_inclusion_proof(&hashes, i);
            let proof = InclusionProof {
                leaf_index: i,
                tree_size: 7,
                proof_hashes,
            };
            assert!(
                verify_inclusion_proof(&hashes[i as usize], &proof, &root).is_ok(),
                "inclusion verification failed for index {}",
                i
            );
        }
    }

    #[test]
    fn test_invalid_inclusion_wrong_leaf() {
        let hashes: Vec<_> = (0..4).map(make_leaf_hash).collect();
        let root = compute_root(&hashes);

        let proof_hashes = generate_inclusion_proof(&hashes, 0);
        let proof = InclusionProof {
            leaf_index: 0,
            tree_size: 4,
            proof_hashes,
        };
        let wrong_hash = make_leaf_hash(99);
        assert!(verify_inclusion_proof(&wrong_hash, &proof, &root).is_err());
    }

    #[test]
    fn test_invalid_inclusion_wrong_root() {
        let hashes: Vec<_> = (0..4).map(make_leaf_hash).collect();
        let wrong_root = [0xFF; 32];

        let proof_hashes = generate_inclusion_proof(&hashes, 0);
        let proof = InclusionProof {
            leaf_index: 0,
            tree_size: 4,
            proof_hashes,
        };
        assert!(verify_inclusion_proof(&hashes[0], &proof, &wrong_root).is_err());
    }

    #[test]
    fn test_verify_sth_signature() {
        use crate::crypto::ed25519::Ed25519KeyPair;

        use crate::crypto::pq_sign;
        let keypair = Ed25519KeyPair::generate();
        let (ml_pk, ml_sk) = pq_sign::pq_sign_keygen();
        let sth = SignedTreeHead {
            tree_size: 5,
            root_hash: [0xAA; 32],
            timestamp: 1700000000,
            signature: vec![], // placeholder
            ml_dsa_signature: vec![],
        };

        let signable = sth.signable_bytes();
        let sig = keypair.sign(&signable);
        let ml_sig = pq_sign::pq_sign(&ml_sk, &signable).unwrap();

        let signed_sth = SignedTreeHead {
            signature: sig,
            ml_dsa_signature: ml_sig,
            ..sth
        };

        assert!(verify_sth(&signed_sth, &keypair.public_key(), &ml_pk).is_ok());
    }

    #[test]
    fn test_reject_bad_sth_signature() {
        use crate::crypto::ed25519::Ed25519KeyPair;

        use crate::crypto::pq_sign;
        let keypair = Ed25519KeyPair::generate();
        let other_keypair = Ed25519KeyPair::generate();
        let (ml_pk, ml_sk) = pq_sign::pq_sign_keygen();

        let sth = SignedTreeHead {
            tree_size: 5,
            root_hash: [0xAA; 32],
            timestamp: 1700000000,
            signature: vec![],
            ml_dsa_signature: vec![],
        };
        let signable = sth.signable_bytes();
        let sig = keypair.sign(&signable);
        let ml_sig = pq_sign::pq_sign(&ml_sk, &signable).unwrap();

        let signed_sth = SignedTreeHead {
            signature: sig,
            ml_dsa_signature: ml_sig,
            ..sth
        };

        // Verify against wrong Ed25519 key — must fail even though the ML-DSA half is valid.
        assert!(verify_sth(&signed_sth, &other_keypair.public_key(), &ml_pk).is_err());
    }

    #[test]
    fn test_verify_sth_requires_ml_dsa() {
        use crate::crypto::ed25519::Ed25519KeyPair;
        use crate::crypto::pq_sign;

        let keypair = Ed25519KeyPair::generate();
        let (ml_pk, ml_sk) = pq_sign::pq_sign_keygen();
        let mut sth = SignedTreeHead {
            tree_size: 7,
            root_hash: [0xBB; 32],
            timestamp: 1700000000,
            signature: vec![],
            ml_dsa_signature: vec![],
        };
        let signable = sth.signable_bytes();
        sth.signature = keypair.sign(&signable);
        sth.ml_dsa_signature = pq_sign::pq_sign(&ml_sk, &signable).unwrap();
        assert!(verify_sth(&sth, &keypair.public_key(), &ml_pk).is_ok());

        // Stripped ML-DSA signature -> rejected even though the Ed25519 half is valid.
        let mut stripped = sth.clone();
        stripped.ml_dsa_signature = Vec::new();
        assert!(verify_sth(&stripped, &keypair.public_key(), &ml_pk).is_err());
    }

    #[test]
    fn test_verify_consistency_2_to_4() {
        let hashes: Vec<_> = (0..4).map(make_leaf_hash).collect();
        let old_root = compute_root(&hashes[..2]);
        let new_root = compute_root(&hashes);

        let proof_hashes = generate_consistency_proof(&hashes, 2, 4);
        let proof = ConsistencyProof {
            old_size: 2,
            new_size: 4,
            proof_hashes,
        };
        assert!(verify_consistency_proof(&proof, &old_root, &new_root).is_ok());
    }

    #[test]
    fn test_verify_consistency_1_to_3() {
        let hashes: Vec<_> = (0..3).map(make_leaf_hash).collect();
        let old_root = compute_root(&hashes[..1]);
        let new_root = compute_root(&hashes);

        let proof_hashes = generate_consistency_proof(&hashes, 1, 3);
        let proof = ConsistencyProof {
            old_size: 1,
            new_size: 3,
            proof_hashes,
        };
        assert!(verify_consistency_proof(&proof, &old_root, &new_root).is_ok());
    }

    #[test]
    fn test_verify_consistency_3_to_7() {
        let hashes: Vec<_> = (0..7).map(make_leaf_hash).collect();
        let old_root = compute_root(&hashes[..3]);
        let new_root = compute_root(&hashes);

        let proof_hashes = generate_consistency_proof(&hashes, 3, 7);
        let proof = ConsistencyProof {
            old_size: 3,
            new_size: 7,
            proof_hashes,
        };
        assert!(verify_consistency_proof(&proof, &old_root, &new_root).is_ok());
    }

    #[test]
    fn test_invalid_consistency_wrong_old_root() {
        let hashes: Vec<_> = (0..4).map(make_leaf_hash).collect();
        let new_root = compute_root(&hashes);

        let proof_hashes = generate_consistency_proof(&hashes, 2, 4);
        let proof = ConsistencyProof {
            old_size: 2,
            new_size: 4,
            proof_hashes,
        };
        let wrong_old = [0xFF; 32];
        assert!(verify_consistency_proof(&proof, &wrong_old, &new_root).is_err());
    }
}
