//! Key transparency verification.

use anyhow::{anyhow, Result};

use echo_crypto::transparency::{
    verify_consistency_proof, verify_inclusion_proof, verify_sth, SignedTreeHead,
    TransparencyProofBundle,
};
use echo_crypto::types::IdentityPublicKey;

const SERVER_TRANSPARENCY_PUBKEY: [u8; 32] = [0u8; 32];

fn is_poc_mode() -> bool {
    SERVER_TRANSPARENCY_PUBKEY == [0u8; 32]
}

pub fn verify_transparency(
    bundle: &TransparencyProofBundle,
    expected_identity_key: &[u8],
    expected_identity_dh_key: &[u8],
    last_sth: Option<&SignedTreeHead>,
    server_pubkey_hex: Option<&str>,
) -> Result<()> {
    // 1. Verify STH signature
    let pubkey = if is_poc_mode() {
        if let Some(hex_key) = server_pubkey_hex {
            let bytes = hex::decode(hex_key)
                .map_err(|_| anyhow!("invalid server transparency public key hex"))?;
            if bytes.len() != 32 {
                return Err(anyhow!("server transparency key must be 32 bytes"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            IdentityPublicKey(arr)
        } else {
            return Err(anyhow!("no server transparency public key available"));
        }
    } else {
        IdentityPublicKey(SERVER_TRANSPARENCY_PUBKEY)
    };

    verify_sth(&bundle.sth, &pubkey)
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

    // 4. Verify consistency with cached STH
    if let (Some(prev_sth), Some(consistency)) = (last_sth, &bundle.consistency_proof) {
        verify_consistency_proof(consistency, &prev_sth.root_hash, &bundle.sth.root_hash)
            .map_err(|_| anyhow!("TRANSPARENCY FAILURE: consistency proof failed — tree was rewritten!"))?;
    }

    Ok(())
}
