//! X4DH: Extended X3DH with post-quantum KEM.
//!
//! Session establishment protocol:
//! 1. DH1 = DH(IK_A, SPK_B)    -- identity to signed prekey
//! 2. DH2 = DH(EK_A, IK_B)     -- ephemeral to identity
//! 3. DH3 = DH(EK_A, SPK_B)    -- ephemeral to signed prekey
//! 4. DH4 = DH(EK_A, OPK_B)    -- ephemeral to one-time prekey (if available)
//! 5. PQ  = KEM.Encaps(PQ_B)   -- post-quantum encapsulation
//!
//! SK = HKDF(DH1 || DH2 || DH3 || DH4 || PQ_SS, "TR3_SESSION_v1")

use crate::crypto::kdf;
use crate::crypto::pq_kem;
use crate::crypto::x25519::X25519KeyPair;
use crate::crypto::ed25519::Ed25519KeyPair;
use crate::error::{EchoError, Result};
use crate::types::*;

/// Result of initiating an X4DH session (Alice's side).
pub struct X4DHInitResult {
    pub root_key: RootKey,
    pub chain_key: ChainKey,
    pub ephemeral_public: PublicKey,
    pub identity_dh_public: PublicKey,   // Alice's X25519 identity DH public (sent to Bob)
    pub pq_ciphertext: PqCiphertext,
    pub used_one_time_prekey_id: Option<u32>,
}

/// Result of responding to an X4DH session (Bob's side).
pub struct X4DHResponseResult {
    pub root_key: RootKey,
    pub chain_key: ChainKey,
}

pub struct X4DH;

impl X4DH {
    /// Initiator (Alice) computes shared secret from Bob's prekey bundle.
    pub fn initiate(
        our_identity: &Ed25519KeyPair,
        our_identity_dh: &X25519KeyPair,
        their_bundle: &PrekeyBundle,
    ) -> Result<X4DHInitResult> {
        // C3: Verify Bob's identity_dh_key is bound to his Ed25519 identity.
        // H2 (Apr 21 audit): the binding check is MANDATORY. An empty signature
        // must not silently skip it — otherwise a compromised server could strip
        // the signature from the prekey bundle and defeat the C3 identity binding,
        // enabling an unknown-key-share attack.
        if their_bundle.identity_dh_key_signature.is_empty() {
            return Err(EchoError::InvalidMessage(
                "prekey bundle missing identity_dh_key binding signature (C3)".into(),
            ));
        }
        let mut dh_bind_msg = Vec::new();
        dh_bind_msg.extend_from_slice(b"echo-dh-binding:");
        dh_bind_msg.extend_from_slice(&their_bundle.identity_dh_key.0);
        Ed25519KeyPair::verify(
            &their_bundle.identity_key,
            &dh_bind_msg,
            &their_bundle.identity_dh_key_signature,
        )?;

        // Verify Bob's signed prekey signature
        let spk_bytes = &their_bundle.signed_prekey.0;
        Ed25519KeyPair::verify(
            &their_bundle.identity_key,
            spk_bytes,
            &their_bundle.signed_prekey_signature,
        )?;

        // Verify Bob's PQ prekey signature
        Ed25519KeyPair::verify(
            &their_bundle.identity_key,
            &their_bundle.pq_prekey.0,
            &their_bundle.pq_prekey_signature,
        )?;

        // Generate ephemeral X25519 key
        let ephemeral = X25519KeyPair::generate();

        // DH1: IK_A × SPK_B
        let dh1 = our_identity_dh.dh(&their_bundle.signed_prekey)?;

        // DH2: EK_A × IK_B (X25519 identity DH key)
        let dh2 = ephemeral.dh(&their_bundle.identity_dh_key)?;

        // DH3: EK_A × SPK_B
        let dh3 = ephemeral.dh(&their_bundle.signed_prekey)?;

        // DH4: EK_A × OPK_B (optional)
        let dh4 = match &their_bundle.one_time_prekey {
            Some(opk) => Some(ephemeral.dh(opk)?),
            None => None,
        };

        // PQ: KEM.Encaps(PQ_PK_B)
        let (pq_ct, pq_ss) = pq_kem::pq_encapsulate(&their_bundle.pq_prekey)?;

        // Combine all shared secrets
        let mut secrets: Vec<&[u8]> = vec![&dh1, &dh2, &dh3];
        if let Some(ref dh4_val) = dh4 {
            secrets.push(dh4_val);
        }
        secrets.push(&pq_ss);

        // M8: Bind session to both parties' identities (initiator=us, responder=them)
        let (root_key, chain_key) = kdf::kdf_session(
            &secrets,
            &our_identity.public_key().0,
            &their_bundle.identity_key.0,
        );

        Ok(X4DHInitResult {
            root_key,
            chain_key,
            ephemeral_public: ephemeral.public_key(),
            identity_dh_public: our_identity_dh.public_key(),
            pq_ciphertext: pq_ct,
            used_one_time_prekey_id: their_bundle.one_time_prekey_id,
        })
    }

    /// Responder (Bob) computes shared secret from Alice's prekey message.
    /// C4: `their_identity_ed` and `their_dh_signature` verify Alice's DH key binding.
    pub fn respond(
        _our_identity: &Ed25519KeyPair,
        our_identity_dh: &X25519KeyPair,
        our_signed_prekey: &X25519KeyPair,
        our_one_time_prekey: Option<&X25519KeyPair>,
        our_pq_secret_key: &PqSecretKey,
        their_identity_dh_key: &PublicKey,
        their_identity_ed: Option<&IdentityPublicKey>,
        their_dh_signature: Option<&[u8]>,
        their_ephemeral: &PublicKey,
        pq_ciphertext: &PqCiphertext,
    ) -> Result<X4DHResponseResult> {
        // C4: Verify Alice's identity_dh_key is bound to her Ed25519 identity.
        // H1/H2 (Apr 21 audit): both the identity key and the binding signature are
        // MANDATORY. The session KDF below binds to `their_identity_ed` (M8); if it
        // were missing we used to fall back to all-zeros, binding the session to a
        // well-known constant and defeating M8. And an empty/absent signature used to
        // skip the C4 check entirely. Reject both cases rather than weaken the binding.
        let their_ed = their_identity_ed.ok_or_else(|| {
            EchoError::InvalidMessage("prekey message missing initiator Ed25519 identity (M8)".into())
        })?;
        let dh_sig = their_dh_signature.filter(|s| !s.is_empty()).ok_or_else(|| {
            EchoError::InvalidMessage("prekey message missing identity_dh_key binding signature (C4)".into())
        })?;
        {
            let mut dh_bind_msg = Vec::new();
            dh_bind_msg.extend_from_slice(b"echo-dh-binding:");
            dh_bind_msg.extend_from_slice(&their_identity_dh_key.0);
            Ed25519KeyPair::verify(their_ed, &dh_bind_msg, dh_sig)?;
        }
        // DH1: SPK_B × IK_A (X25519 identity DH key)
        let dh1 = our_signed_prekey.dh(their_identity_dh_key)?;

        // DH2: IK_B × EK_A
        let dh2 = our_identity_dh.dh(their_ephemeral)?;

        // DH3: SPK_B × EK_A
        let dh3 = our_signed_prekey.dh(their_ephemeral)?;

        // DH4: OPK_B × EK_A (optional)
        let dh4 = match our_one_time_prekey {
            Some(opk) => Some(opk.dh(their_ephemeral)?),
            None => None,
        };

        // PQ: KEM.Decaps(ct, PQ_SK_B)
        let pq_ss = pq_kem::pq_decapsulate(pq_ciphertext, our_pq_secret_key)?;

        // Combine (same order as initiator)
        let mut secrets: Vec<&[u8]> = vec![&dh1, &dh2, &dh3];
        if let Some(ref dh4_val) = dh4 {
            secrets.push(dh4_val);
        }
        secrets.push(&pq_ss);

        // M8: Bind session to both parties' identities (initiator=them, responder=us).
        // `their_ed` was validated as present above (H1) — no zero fallback.
        let (root_key, chain_key) = kdf::kdf_session(
            &secrets,
            &their_ed.0,
            &_our_identity.public_key().0,
        );

        Ok(X4DHResponseResult {
            root_key,
            chain_key,
        })
    }
}
