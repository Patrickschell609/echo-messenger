//! Integration tests for the ECHO key transparency system.
//!
//! Tests the full flow: key upload → tree build → proof generation → verification.
//! Also tests attack detection: key swaps, tree rewrites, and omissions.

use echo_crypto::crypto::ed25519::Ed25519KeyPair;
use echo_crypto::transparency::*;

// ─── Helpers ───

fn make_leaf(device_idx: u8, seq: i64) -> TransparencyLeaf {
    use sha2::{Digest, Sha256};
    // Use wrapping arithmetic to avoid overflow for large device_idx values
    let ik = device_idx.wrapping_mul(3).wrapping_add(1);
    let dk = device_idx.wrapping_mul(3).wrapping_add(2);
    let sk = device_idx.wrapping_mul(3).wrapping_add(3);
    TransparencyLeaf {
        device_id: vec![device_idx; 16],
        identity_key: vec![ik; 32],
        identity_dh_key: vec![dk; 32],
        signed_prekey: vec![sk; 32],
        pq_prekey_hash: Sha256::digest(&vec![device_idx; 1568]).to_vec(),
        timestamp: 1700000000 + seq as u64,
        sequence_id: seq,
    }
}

fn build_signed_tree(
    leaves: &[TransparencyLeaf],
    keypair: &Ed25519KeyPair,
) -> (Vec<[u8; 32]>, SignedTreeHead) {
    let hashes: Vec<[u8; 32]> = leaves.iter().map(|l| l.hash()).collect();
    let root = compute_root(&hashes);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut sth = SignedTreeHead {
        tree_size: hashes.len() as u64,
        root_hash: root,
        timestamp: now,
        signature: vec![],
    };
    sth.signature = keypair.sign(&sth.signable_bytes());

    (hashes, sth)
}

// ─── Test: Full Transparency Flow ───

#[test]
fn test_full_transparency_flow() {
    let server_key = Ed25519KeyPair::generate();

    // Simulate 5 devices uploading keys
    let leaves: Vec<_> = (0..5u8).map(|i| make_leaf(i, i as i64 + 1)).collect();
    let (hashes, sth) = build_signed_tree(&leaves, &server_key);

    // Verify STH signature
    assert!(verify_sth(&sth, &server_key.public_key()).is_ok());

    // Generate and verify inclusion proof for each device
    for (i, leaf) in leaves.iter().enumerate() {
        let proof_hashes = generate_inclusion_proof(&hashes, i as u64);
        let proof = InclusionProof {
            leaf_index: i as u64,
            tree_size: hashes.len() as u64,
            proof_hashes,
        };

        let leaf_hash = leaf.hash();
        assert!(
            verify_inclusion_proof(&leaf_hash, &proof, &sth.root_hash).is_ok(),
            "inclusion proof failed for device {}",
            i
        );
    }
}

// ─── Test: Key Swap Detection ───

#[test]
fn test_swapped_key_detection() {
    let server_key = Ed25519KeyPair::generate();

    // Server has Alice's real keys in the tree
    let alice = make_leaf(0, 1);
    let bob = make_leaf(1, 2);
    let leaves = vec![alice.clone(), bob.clone()];
    let (hashes, sth) = build_signed_tree(&leaves, &server_key);

    // Generate proof for Alice's position
    let proof_hashes = generate_inclusion_proof(&hashes, 0);
    let proof = InclusionProof {
        leaf_index: 0,
        tree_size: 2,
        proof_hashes,
    };

    // Verify with Alice's real keys — should pass
    let alice_hash = alice.hash();
    assert!(verify_inclusion_proof(&alice_hash, &proof, &sth.root_hash).is_ok());

    // Now: server tries to serve SWAPPED keys (Evil's keys instead of Alice's)
    let evil = make_leaf(99, 1); // Different keys
    let evil_hash = evil.hash();

    // Proof should FAIL because evil's leaf hash doesn't match the tree
    assert!(
        verify_inclusion_proof(&evil_hash, &proof, &sth.root_hash).is_err(),
        "swapped keys should be detected!"
    );
}

// ─── Test: Tree Rewrite Detection ───

#[test]
fn test_tree_rewrite_detection() {
    let server_key = Ed25519KeyPair::generate();

    // Original tree: Alice and Bob
    let alice = make_leaf(0, 1);
    let bob = make_leaf(1, 2);
    let original_leaves = vec![alice.clone(), bob.clone()];
    let (_, original_sth) = build_signed_tree(&original_leaves, &server_key);

    // Tree grows normally: Charlie joins
    let charlie = make_leaf(2, 3);
    let grown_leaves = vec![alice.clone(), bob.clone(), charlie.clone()];
    let (grown_hashes, grown_sth) = build_signed_tree(&grown_leaves, &server_key);

    // Normal consistency proof should pass
    let consistency_hashes =
        generate_consistency_proof(&grown_hashes, 2, 3);
    let proof = ConsistencyProof {
        old_size: 2,
        new_size: 3,
        proof_hashes: consistency_hashes,
    };
    assert!(verify_consistency_proof(
        &proof,
        &original_sth.root_hash,
        &grown_sth.root_hash
    )
    .is_ok());

    // Attack: server REWRITES the tree (replaces Bob with Evil)
    let evil = make_leaf(99, 2);
    let rewritten_leaves = vec![alice.clone(), evil, charlie.clone()];
    let (_, rewritten_sth) = build_signed_tree(&rewritten_leaves, &server_key);

    // Client has the original STH cached. The rewritten tree has a different root.
    // A consistency proof between original root and rewritten root should FAIL
    // because the original tree is NOT a prefix of the rewritten tree.
    assert_ne!(
        original_sth.root_hash, rewritten_sth.root_hash,
        "rewritten tree should have different root"
    );

    // The server cannot produce a valid consistency proof
    // (We verify by checking that the real proof from the rewritten tree
    //  doesn't match the original root)
    let rewritten_hashes: Vec<_> = rewritten_leaves.iter().map(|l| l.hash()).collect();
    let bad_consistency = generate_consistency_proof(&rewritten_hashes, 2, 3);
    let bad_proof = ConsistencyProof {
        old_size: 2,
        new_size: 3,
        proof_hashes: bad_consistency,
    };
    assert!(
        verify_consistency_proof(
            &bad_proof,
            &original_sth.root_hash, // client's cached original root
            &rewritten_sth.root_hash  // server's new rewritten root
        )
        .is_err(),
        "tree rewrite should be detected!"
    );
}

// ─── Test: Legitimate Key Rotation ───

#[test]
fn test_key_rotation_legitimate() {
    let server_key = Ed25519KeyPair::generate();

    // Alice registers
    let alice_v1 = make_leaf(0, 1);
    let leaves_v1 = vec![alice_v1.clone()];
    let (hashes_v1, sth_v1) = build_signed_tree(&leaves_v1, &server_key);

    // Alice rotates keys — new leaf is APPENDED
    let mut alice_v2 = make_leaf(0, 2);
    alice_v2.signed_prekey = vec![0xFF; 32]; // New signed prekey

    let leaves_v2 = vec![alice_v1.clone(), alice_v2.clone()];
    let (hashes_v2, sth_v2) = build_signed_tree(&leaves_v2, &server_key);

    // Consistency proof should pass (tree grew from 1 to 2)
    let consistency = generate_consistency_proof(&hashes_v2, 1, 2);
    let proof = ConsistencyProof {
        old_size: 1,
        new_size: 2,
        proof_hashes: consistency,
    };
    assert!(verify_consistency_proof(
        &proof,
        &sth_v1.root_hash,
        &sth_v2.root_hash
    )
    .is_ok());

    // Inclusion proof for the NEW leaf (latest = index 1)
    let inc_proof_hashes = generate_inclusion_proof(&hashes_v2, 1);
    let inc_proof = InclusionProof {
        leaf_index: 1,
        tree_size: 2,
        proof_hashes: inc_proof_hashes,
    };
    assert!(verify_inclusion_proof(&alice_v2.hash(), &inc_proof, &sth_v2.root_hash).is_ok());
}

// ─── Test: Omission Attack ───

#[test]
fn test_omission_attack() {
    let server_key = Ed25519KeyPair::generate();

    // Alice and Bob are in the tree
    let alice = make_leaf(0, 1);
    let bob = make_leaf(1, 2);
    let leaves = vec![alice.clone(), bob.clone()];
    let (hashes, sth) = build_signed_tree(&leaves, &server_key);

    // Charlie is NOT in the tree. Server cannot produce a valid inclusion proof.
    let charlie = make_leaf(2, 3);
    let charlie_hash = charlie.hash();

    // Try to verify Charlie with a proof that doesn't exist
    // Using an empty proof should fail
    let fake_proof = InclusionProof {
        leaf_index: 0,
        tree_size: 2,
        proof_hashes: vec![],
    };
    assert!(
        verify_inclusion_proof(&charlie_hash, &fake_proof, &sth.root_hash).is_err(),
        "omission attack should be detected"
    );

    // Even trying to use Alice's proof with Charlie's hash should fail
    let alice_proof_hashes = generate_inclusion_proof(&hashes, 0);
    let mismatched_proof = InclusionProof {
        leaf_index: 0,
        tree_size: 2,
        proof_hashes: alice_proof_hashes,
    };
    assert!(
        verify_inclusion_proof(&charlie_hash, &mismatched_proof, &sth.root_hash).is_err(),
        "using someone else's proof should fail"
    );
}

// ─── Test: STH Signature Verification ───

#[test]
fn test_sth_wrong_key_rejected() {
    let server_key = Ed25519KeyPair::generate();
    let attacker_key = Ed25519KeyPair::generate();

    let leaves = vec![make_leaf(0, 1)];
    let (_, sth) = build_signed_tree(&leaves, &server_key);

    // Verify with correct key
    assert!(verify_sth(&sth, &server_key.public_key()).is_ok());

    // Verify with attacker key — should fail
    assert!(verify_sth(&sth, &attacker_key.public_key()).is_err());
}

#[test]
fn test_sth_tampered_root_rejected() {
    let server_key = Ed25519KeyPair::generate();

    let leaves = vec![make_leaf(0, 1), make_leaf(1, 2)];
    let (_, mut sth) = build_signed_tree(&leaves, &server_key);

    // Tamper with the root hash
    sth.root_hash[0] ^= 0xFF;

    // Signature should no longer be valid
    assert!(verify_sth(&sth, &server_key.public_key()).is_err());
}

// ─── Test: Large Tree ───

#[test]
fn test_large_tree_100_entries() {
    let server_key = Ed25519KeyPair::generate();

    // Build a tree with 100 entries
    let leaves: Vec<_> = (0..100u8).map(|i| make_leaf(i, i as i64 + 1)).collect();
    let (hashes, sth) = build_signed_tree(&leaves, &server_key);

    assert!(verify_sth(&sth, &server_key.public_key()).is_ok());

    // Verify inclusion for every leaf
    for i in 0..100u64 {
        let proof_hashes = generate_inclusion_proof(&hashes, i);
        let proof = InclusionProof {
            leaf_index: i,
            tree_size: 100,
            proof_hashes,
        };
        assert!(
            verify_inclusion_proof(&hashes[i as usize], &proof, &sth.root_hash).is_ok(),
            "inclusion proof failed for index {} in 100-entry tree",
            i
        );
    }

    // Consistency: tree grew from 50 to 100
    let consistency = generate_consistency_proof(&hashes, 50, 100);
    let old_root = compute_root(&hashes[..50]);
    let proof = ConsistencyProof {
        old_size: 50,
        new_size: 100,
        proof_hashes: consistency,
    };
    assert!(verify_consistency_proof(&proof, &old_root, &sth.root_hash).is_ok());
}

// ─── Test: FFI Function ───

#[test]
fn test_ffi_verify_transparency_proof() {
    let server_key = Ed25519KeyPair::generate();

    // Build a small tree
    let leaf = make_leaf(0, 1);
    let leaves = vec![leaf.clone()];
    let (hashes, sth) = build_signed_tree(&leaves, &server_key);

    let proof_hashes = generate_inclusion_proof(&hashes, 0);
    let inclusion = InclusionProof {
        leaf_index: 0,
        tree_size: 1,
        proof_hashes,
    };

    let bundle = TransparencyProofBundle {
        sth: sth.clone(),
        inclusion_proof: inclusion,
        leaf: leaf.clone(),
        consistency_proof: None,
    };

    let proof_json = serde_json::to_string(&bundle).unwrap();

    let result = echo_crypto::ffi_api::ffi_verify_transparency_proof(
        proof_json,
        server_key.public_key().0.to_vec(),
        leaf.identity_key.clone(),
        leaf.identity_dh_key.clone(),
        None,
    );

    assert!(result.is_ok(), "FFI verification should pass: {:?}", result.err());

    // Verify the returned STH can be parsed back
    let new_sth: SignedTreeHead = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(new_sth.tree_size, 1);
}

#[test]
fn test_ffi_verify_rejects_wrong_keys() {
    let server_key = Ed25519KeyPair::generate();

    let leaf = make_leaf(0, 1);
    let leaves = vec![leaf.clone()];
    let (hashes, sth) = build_signed_tree(&leaves, &server_key);

    let inclusion = InclusionProof {
        leaf_index: 0,
        tree_size: 1,
        proof_hashes: generate_inclusion_proof(&hashes, 0),
    };

    let bundle = TransparencyProofBundle {
        sth,
        inclusion_proof: inclusion,
        leaf: leaf.clone(),
        consistency_proof: None,
    };

    let proof_json = serde_json::to_string(&bundle).unwrap();

    // Pass wrong expected identity key
    let result = echo_crypto::ffi_api::ffi_verify_transparency_proof(
        proof_json,
        server_key.public_key().0.to_vec(),
        vec![0xFF; 32], // wrong key
        leaf.identity_dh_key.clone(),
        None,
    );

    assert!(result.is_err(), "should reject mismatched identity key");
    assert!(result.unwrap_err().contains("mismatch"));
}
