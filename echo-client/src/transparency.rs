//! Key transparency verification.

use anyhow::{anyhow, Result};

use echo_crypto::transparency::{
    verify_consistency_proof, verify_inclusion_proof, verify_sth, SignedTreeHead,
    TransparencyProofBundle,
};
use echo_crypto::types::IdentityPublicKey;

const SERVER_TRANSPARENCY_PUBKEY: [u8; 32] = [
    0x4a, 0x27, 0xcc, 0xd7, 0x5a, 0xac, 0xb5, 0xa5,
    0xc1, 0x31, 0x19, 0x0d, 0x9c, 0x2f, 0xc9, 0xb7,
    0xe0, 0xb3, 0x89, 0x55, 0x32, 0x2c, 0x9d, 0x5a,
    0xd9, 0x1e, 0xfc, 0xb2, 0xe2, 0x07, 0x88, 0x32,
];

pub fn verify_transparency(
    bundle: &TransparencyProofBundle,
    expected_identity_key: &[u8],
    expected_identity_dh_key: &[u8],
    last_sth: Option<&SignedTreeHead>,
    server_pubkey_hex: Option<&str>,
    server_ml_dsa_pubkey: &[u8],
) -> Result<()> {
    // 1. Verify STH hybrid signature. The Ed25519 key is pinned in the binary
    // (primary anchor); the ML-DSA key is supplied by the caller from its cache
    // and adds post-quantum protection on top of the pin.
    let _ = server_pubkey_hex; // no longer needed — Ed25519 key is hardcoded
    let pubkey = IdentityPublicKey(SERVER_TRANSPARENCY_PUBKEY);

    verify_sth(&bundle.sth, &pubkey, server_ml_dsa_pubkey)
        .map_err(|_| anyhow!("TRANSPARENCY FAILURE: STH signature invalid"))?;

    // 2. Verify leaf matches fetched keys
    if bundle.leaf.identity_key != expected_identity_key {
        return Err(anyhow!(
            "TRANSPARENCY FAILURE: identity_key in transparency log doesn't match fetched key"
        ));
    }
    if bundle.leaf.identity_dh_key != expected_identity_dh_key {
        return Err(anyhow!(
            "TRANSPARENCY FAILURE: identity_dh_key in transparency log doesn't match fetched key"
        ));
    }

    // 3. Verify inclusion proof
    let leaf_hash = bundle.leaf.hash();
    verify_inclusion_proof(&leaf_hash, &bundle.inclusion_proof, &bundle.sth.root_hash)
        .map_err(|_| anyhow!("TRANSPARENCY FAILURE: inclusion proof invalid"))?;

    // 4. Verify consistency with cached STH — MANDATORY when we have a previous STH
    if let Some(prev_sth) = last_sth {
        let consistency = bundle.consistency_proof.as_ref()
            .ok_or_else(|| anyhow!(
                "TRANSPARENCY FAILURE: server omitted consistency proof — possible tree rewrite"
            ))?;
        verify_consistency_proof(consistency, &prev_sth.root_hash, &bundle.sth.root_hash)
            .map_err(|_| anyhow!("TRANSPARENCY FAILURE: consistency proof failed — tree was rewritten!"))?;
    }

    Ok(())
}
