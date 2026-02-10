use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::types::{ChainKey, HeaderKey, MessageKey, RootKey, SymmetricKey};

/// Domain separation constants
const ROOT_INFO: &[u8] = b"TR3_ROOT_v1";
const CHAIN_INFO: &[u8] = b"TR3_CHAIN_v1";
const MESSAGE_INFO: &[u8] = b"TR3_MSG_v1";
const HEADER_INFO: &[u8] = b"TR3_HDR_v1";
const EPOCH_INFO: &[u8] = b"TR3_EPOCH_v1";
const SESSION_INFO: &[u8] = b"TR3_SESSION_v1";

/// HKDF-SHA256 extract and expand.
pub fn hkdf_derive(salt: &[u8], ikm: &[u8], info: &[u8], output_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; output_len];
    hk.expand(info, &mut okm)
        .expect("HKDF output length valid");
    okm
}

/// Root key KDF: combines DH output (and optionally PQ output) with current root key.
/// Returns (new_root_key, new_chain_key).
pub fn kdf_root(root_key: &RootKey, dh_output: &[u8]) -> (RootKey, ChainKey) {
    let derived = hkdf_derive(&root_key.0, dh_output, ROOT_INFO, 64);
    let mut root = [0u8; 32];
    let mut chain = [0u8; 32];
    root.copy_from_slice(&derived[..32]);
    chain.copy_from_slice(&derived[32..]);
    (RootKey(root), ChainKey(chain))
}

/// Root key KDF with combined DH + PQ shared secrets (Triple Ratchet core).
/// root_key' = HKDF(root_key, DH_shared || KEM_shared, "TR3_ROOT_v1")
pub fn kdf_root_combined(
    root_key: &RootKey,
    dh_output: &[u8],
    pq_output: &[u8],
) -> (RootKey, ChainKey) {
    let mut combined = Vec::with_capacity(dh_output.len() + pq_output.len());
    combined.extend_from_slice(dh_output);
    combined.extend_from_slice(pq_output);

    let result = kdf_root_raw(&root_key.0, &combined);
    combined.zeroize();
    result
}

fn kdf_root_raw(salt: &[u8; 32], ikm: &[u8]) -> (RootKey, ChainKey) {
    let derived = hkdf_derive(salt, ikm, ROOT_INFO, 64);
    let mut root = [0u8; 32];
    let mut chain = [0u8; 32];
    root.copy_from_slice(&derived[..32]);
    chain.copy_from_slice(&derived[32..]);
    (RootKey(root), ChainKey(chain))
}

/// Chain key KDF: advance the symmetric ratchet one step.
/// Returns (new_chain_key, message_key).
pub fn kdf_chain(chain_key: &ChainKey) -> (ChainKey, MessageKey) {
    let new_chain = hkdf_derive(&chain_key.0, &[0x02], CHAIN_INFO, 32);
    let msg_key = hkdf_derive(&chain_key.0, &[0x01], MESSAGE_INFO, 32);

    let mut ck = [0u8; 32];
    let mut mk = [0u8; 32];
    ck.copy_from_slice(&new_chain);
    mk.copy_from_slice(&msg_key);

    (ChainKey(ck), MessageKey(mk))
}

/// Derive header encryption key from root key + direction.
pub fn derive_header_key(root_key: &RootKey, sending: bool) -> HeaderKey {
    let direction = if sending { b"send" as &[u8] } else { b"recv" };
    let derived = hkdf_derive(&root_key.0, direction, HEADER_INFO, 32);
    let mut hk = [0u8; 32];
    hk.copy_from_slice(&derived);
    HeaderKey(hk)
}

/// Derive session key from X4DH output (initial session establishment).
pub fn kdf_session(shared_secrets: &[&[u8]]) -> (RootKey, ChainKey) {
    // Concatenate all DH outputs from X4DH
    let total_len: usize = shared_secrets.iter().map(|s| s.len()).sum();
    let mut combined = Vec::with_capacity(total_len);
    for secret in shared_secrets {
        combined.extend_from_slice(secret);
    }

    let salt = [0u8; 32]; // X3DH spec uses zero salt
    let derived = hkdf_derive(&salt, &combined, SESSION_INFO, 64);
    combined.zeroize();

    let mut root = [0u8; 32];
    let mut chain = [0u8; 32];
    root.copy_from_slice(&derived[..32]);
    chain.copy_from_slice(&derived[32..]);
    (RootKey(root), ChainKey(chain))
}

/// Derive epoch key from PQ KEM shared secret.
pub fn kdf_epoch(current_root: &RootKey, pq_shared_secret: &[u8]) -> RootKey {
    let derived = hkdf_derive(&current_root.0, pq_shared_secret, EPOCH_INFO, 32);
    let mut root = [0u8; 32];
    root.copy_from_slice(&derived);
    RootKey(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_chain_produces_different_keys() {
        let ck = ChainKey([42u8; 32]);
        let (ck2, mk1) = kdf_chain(&ck);
        let (ck3, mk2) = kdf_chain(&ck2);

        assert_ne!(ck.0, ck2.0);
        assert_ne!(ck2.0, ck3.0);
        assert_ne!(mk1.0, mk2.0);
    }

    #[test]
    fn test_kdf_root_deterministic() {
        let rk = RootKey([1u8; 32]);
        let dh = [2u8; 32];

        let (rk1, ck1) = kdf_root(&rk, &dh);
        let (rk2, ck2) = kdf_root(&rk, &dh);

        assert_eq!(rk1.0, rk2.0);
        assert_eq!(ck1.0, ck2.0);
    }

    #[test]
    fn test_kdf_combined_differs_from_dh_only() {
        let rk = RootKey([1u8; 32]);
        let dh = [2u8; 32];
        let pq = [3u8; 32];

        let (rk_dh, _) = kdf_root(&rk, &dh);
        let (rk_combined, _) = kdf_root_combined(&rk, &dh, &pq);

        assert_ne!(rk_dh.0, rk_combined.0);
    }
}
