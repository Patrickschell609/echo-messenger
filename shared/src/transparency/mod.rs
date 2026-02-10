//! Key Transparency for ECHO Messenger.
//!
//! Implements RFC 6962-style Merkle tree with:
//! - Signed Tree Heads (STH) — server commits to tree state
//! - Inclusion proofs — prove a key exists in the tree
//! - Consistency proofs — prove the tree only grows (append-only)
//!
//! When Alice fetches Bob's prekey bundle, she also gets a
//! TransparencyProofBundle that lets her verify the server
//! isn't lying about Bob's keys.

pub mod types;
pub mod merkle;
pub mod proof;

pub use types::*;
pub use merkle::{compute_root, generate_inclusion_proof, generate_consistency_proof, hash_children};
pub use proof::{verify_inclusion_proof, verify_consistency_proof, verify_sth};
