use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use echo_crypto::transparency::{
    self, ConsistencyProof, InclusionProof, SignedTreeHead, TransparencyLeaf,
    TransparencyProofBundle,
};

use super::{authenticate_device, ApiError, AppState};

/// POST /v1/keys/upload
/// Upload identity key, signed prekey, PQ prekey, and one-time prekeys.
/// Creates the device record if it doesn't exist.
#[derive(Deserialize)]
pub struct UploadPrekeysRequest {
    pub account_id: Uuid,
    /// Ed25519 identity public key (32 bytes, hex)
    pub identity_key: String,
    /// X25519 identity DH public key (32 bytes, hex)
    pub identity_dh_key: String,
    /// X25519 signed prekey (32 bytes, hex)
    pub signed_prekey: String,
    /// Ed25519 signature of signed prekey (64 bytes, hex)
    pub signed_prekey_sig: String,
    pub signed_prekey_id: i32,
    /// ML-KEM-1024 public key (hex)
    pub pq_prekey: Option<String>,
    /// Ed25519 signature of PQ prekey (hex)
    pub pq_prekey_sig: Option<String>,
    pub pq_prekey_id: Option<i32>,
    /// One-time prekeys: list of (key_id, public_key_hex)
    pub one_time_prekeys: Vec<OneTimePrekey>,
    /// Auth nonce from registration (hex, required for new devices)
    pub auth_nonce: Option<String>,
    /// Ed25519 signature proving identity_key ownership: sign("echo-key-upload:" || account_id || identity_key_bytes)
    pub auth_signature: Option<String>,
}

#[derive(Deserialize)]
pub struct OneTimePrekey {
    pub key_id: i32,
    pub public_key: String,
}

#[derive(Serialize)]
pub struct UploadPrekeysResponse {
    pub device_id: Uuid,
    /// Server-signed sender certificate for sealed sender (hex-encoded bincode)
    pub sender_cert: Option<String>,
}

pub async fn upload_prekeys(
    State(state): State<AppState>,
    Json(req): Json<UploadPrekeysRequest>,
) -> Result<Json<UploadPrekeysResponse>, ApiError> {
    let identity_key = hex::decode(&req.identity_key)
        .map_err(|_| ApiError::BadRequest("invalid identity_key hex".into()))?;
    let identity_dh_key = hex::decode(&req.identity_dh_key)
        .map_err(|_| ApiError::BadRequest("invalid identity_dh_key hex".into()))?;
    let signed_prekey = hex::decode(&req.signed_prekey)
        .map_err(|_| ApiError::BadRequest("invalid signed_prekey hex".into()))?;
    let signed_prekey_sig = hex::decode(&req.signed_prekey_sig)
        .map_err(|_| ApiError::BadRequest("invalid signed_prekey_sig hex".into()))?;

    if identity_key.len() != 32 || identity_dh_key.len() != 32 || signed_prekey.len() != 32 {
        return Err(ApiError::BadRequest("key size mismatch".into()));
    }

    // Verify Ed25519 signature proving identity_key ownership
    let auth_sig_bytes = req.auth_signature.as_ref()
        .map(|h| hex::decode(h))
        .transpose()
        .map_err(|_| ApiError::BadRequest("invalid auth_signature hex".into()))?;

    if let Some(ref sig_bytes) = auth_sig_bytes {
        if sig_bytes.len() != 64 {
            return Err(ApiError::BadRequest("auth_signature must be 64 bytes".into()));
        }
        // Verify: sign("echo-key-upload:" || account_id || identity_key_bytes)
        let mut msg = Vec::new();
        msg.extend_from_slice(b"echo-key-upload:");
        msg.extend_from_slice(req.account_id.as_bytes());
        msg.extend_from_slice(&identity_key);

        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&identity_key);
        let vk = VerifyingKey::from_bytes(&pk)
            .map_err(|_| ApiError::BadRequest("invalid identity_key for Ed25519".into()))?;
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(sig_bytes);
        let sig = Signature::from_bytes(&sig_arr);
        vk.verify(&msg, &sig)
            .map_err(|_| ApiError::Unauthorized)?;
    }

    // Check if this is a new device or key rotation
    let existing_device: Option<(Uuid, Vec<u8>)> = sqlx::query_as(
        "SELECT id, identity_key FROM devices WHERE account_id = $1 AND identity_key = $2"
    )
    .bind(req.account_id)
    .bind(&identity_key)
    .fetch_optional(&state.db)
    .await?;

    if existing_device.is_none() {
        // New device: require auth_nonce from registration
        let nonce_hex = req.auth_nonce.as_ref()
            .ok_or_else(|| ApiError::Unauthorized)?;
        let nonce_bytes = hex::decode(nonce_hex)
            .map_err(|_| ApiError::BadRequest("invalid auth_nonce hex".into()))?;

        // Verify and consume nonce atomically
        let consumed: Option<(Uuid,)> = sqlx::query_as(
            r#"
            UPDATE accounts
            SET auth_nonce = NULL, auth_nonce_expires_at = NULL
            WHERE id = $1
              AND auth_nonce = $2
              AND auth_nonce_expires_at > NOW()
            RETURNING id
            "#
        )
        .bind(req.account_id)
        .bind(&nonce_bytes)
        .fetch_optional(&state.db)
        .await?;

        if consumed.is_none() {
            return Err(ApiError::Unauthorized);
        }

        // Also require signature for new device
        if auth_sig_bytes.is_none() {
            return Err(ApiError::BadRequest("auth_signature required for new device".into()));
        }
    } else {
        // Key rotation: verify signature against STORED identity_key (not request body)
        // The signature was already verified above against the identity_key in the request.
        // Since existing_device matched on the same identity_key, this is consistent.
        if auth_sig_bytes.is_none() {
            return Err(ApiError::BadRequest("auth_signature required for key rotation".into()));
        }
    }

    let pq_prekey = req.pq_prekey.as_ref().map(|h| hex::decode(h))
        .transpose()
        .map_err(|_| ApiError::BadRequest("invalid pq_prekey hex".into()))?;
    let pq_prekey_sig = req.pq_prekey_sig.as_ref().map(|h| hex::decode(h))
        .transpose()
        .map_err(|_| ApiError::BadRequest("invalid pq_prekey_sig hex".into()))?;

    // Upsert device (insert or update on conflict)
    let (device_id,): (Uuid,) = sqlx::query_as(
        r#"
        INSERT INTO devices (account_id, identity_key, identity_dh_key, signed_prekey, signed_prekey_sig, signed_prekey_id, pq_prekey, pq_prekey_sig, pq_prekey_id, last_seen)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
        ON CONFLICT (account_id, identity_key) DO UPDATE SET
            identity_dh_key = EXCLUDED.identity_dh_key,
            signed_prekey = EXCLUDED.signed_prekey,
            signed_prekey_sig = EXCLUDED.signed_prekey_sig,
            signed_prekey_id = EXCLUDED.signed_prekey_id,
            pq_prekey = EXCLUDED.pq_prekey,
            pq_prekey_sig = EXCLUDED.pq_prekey_sig,
            pq_prekey_id = EXCLUDED.pq_prekey_id,
            last_seen = NOW()
        RETURNING id
        "#
    )
    .bind(req.account_id)
    .bind(&identity_key)
    .bind(&identity_dh_key)
    .bind(&signed_prekey)
    .bind(&signed_prekey_sig)
    .bind(req.signed_prekey_id)
    .bind(&pq_prekey)
    .bind(&pq_prekey_sig)
    .bind(req.pq_prekey_id)
    .fetch_one(&state.db)
    .await?;

    // Insert one-time prekeys
    for otpk in &req.one_time_prekeys {
        let pk = hex::decode(&otpk.public_key)
            .map_err(|_| ApiError::BadRequest("invalid one_time_prekey hex".into()))?;
        sqlx::query(
            r#"
            INSERT INTO onetime_prekeys (device_id, key_id, public_key)
            VALUES ($1, $2, $3)
            ON CONFLICT (device_id, key_id) DO NOTHING
            "#
        )
        .bind(device_id)
        .bind(otpk.key_id)
        .bind(&pk)
        .execute(&state.db)
        .await?;
    }

    // Hash PQ prekey for transparency log (avoid storing 1568 bytes in log)
    let pq_prekey_hash = pq_prekey.as_ref().map(|pk| sha256(pk));

    // Log to key transparency with full key data
    let ik_hash = sha256(&identity_key);
    sqlx::query(
        r#"
        INSERT INTO key_transparency_log
            (device_id, identity_key_hash, identity_key, identity_dh_key, signed_prekey, pq_prekey_hash)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#
    )
    .bind(device_id)
    .bind(&ik_hash)
    .bind(&identity_key)
    .bind(&identity_dh_key)
    .bind(&signed_prekey)
    .bind(&pq_prekey_hash)
    .execute(&state.db)
    .await?;

    // Generate server-signed sender certificate
    let mut device_bytes = [0u8; 16];
    device_bytes.copy_from_slice(device_id.as_bytes());

    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 86400; // 24 hours

    // Sign: device_id_bytes || identity_key_bytes || expiry_le_bytes
    let mut cert_msg = Vec::new();
    cert_msg.extend_from_slice(&device_bytes);
    cert_msg.extend_from_slice(&identity_key);
    cert_msg.extend_from_slice(&expiry.to_le_bytes());
    let server_sig = state.transparency_key.sign(&cert_msg);

    let sender_cert = echo_crypto::sealed_sender::SenderCertificate {
        sender_identity: echo_crypto::IdentityPublicKey({
            let mut ik = [0u8; 32];
            ik.copy_from_slice(&identity_key);
            ik
        }),
        sender_device_id: echo_crypto::DeviceId(device_bytes),
        expiry,
        server_signature: server_sig,
    };

    let cert_bytes = bincode::serialize(&sender_cert).ok();
    let cert_hex = cert_bytes.map(|b| hex::encode(b));

    tracing::info!("device {} uploaded prekeys ({} one-time)", device_id, req.one_time_prekeys.len());
    Ok(Json(UploadPrekeysResponse {
        device_id,
        sender_cert: cert_hex,
    }))
}

/// GET /v1/keys/:device_id
/// Fetch a device's prekey bundle. Pops one one-time prekey atomically.
/// Now includes transparency proof bundle.
#[derive(Serialize)]
pub struct FetchPrekeysResponse {
    pub identity_key: String,
    pub identity_dh_key: String,
    pub signed_prekey: String,
    pub signed_prekey_sig: String,
    pub signed_prekey_id: i32,
    pub pq_prekey: Option<String>,
    pub pq_prekey_sig: Option<String>,
    pub pq_prekey_id: Option<i32>,
    pub one_time_prekey: Option<String>,
    pub one_time_prekey_id: Option<i32>,
    /// Key transparency proof bundle (null if transparency log is empty)
    pub transparency: Option<TransparencyProofBundle>,
}

pub async fn fetch_prekeys(
    State(state): State<AppState>,
    Path(device_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<FetchPrekeysResponse>, ApiError> {
    // Require Ed25519 authentication
    let path = format!("/v1/keys/{}", device_id);
    let _requester = authenticate_device(&headers, "GET", &path, &state.db).await?;

    // Check if client sent their last-seen tree size (for consistency proof)
    let client_tree_size: Option<u64> = headers
        .get("x-kt-tree-size")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    // Fetch device keys
    let row: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i32, Option<Vec<u8>>, Option<Vec<u8>>, Option<i32>) =
        sqlx::query_as(
            r#"
            SELECT identity_key, identity_dh_key, signed_prekey, signed_prekey_sig, signed_prekey_id,
                   pq_prekey, pq_prekey_sig, pq_prekey_id
            FROM devices WHERE id = $1
            "#
        )
        .bind(device_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("device not found".into()))?;

    // Pop one one-time prekey atomically (FIFO)
    let otpk: Option<(i32, Vec<u8>)> = sqlx::query_as(
        r#"
        DELETE FROM onetime_prekeys
        WHERE id = (
            SELECT id FROM onetime_prekeys
            WHERE device_id = $1
            ORDER BY id ASC
            LIMIT 1
            FOR UPDATE SKIP LOCKED
        )
        RETURNING key_id, public_key
        "#
    )
    .bind(device_id)
    .fetch_optional(&state.db)
    .await?;

    // Check remaining count and warn
    let (remaining,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM onetime_prekeys WHERE device_id = $1"
    )
    .bind(device_id)
    .fetch_one(&state.db)
    .await?;

    if remaining < 10 {
        tracing::warn!("device {} has only {} one-time prekeys left", device_id, remaining);
    }

    // Build transparency proof
    let transparency = build_transparency_proof(
        &state,
        device_id,
        client_tree_size,
    )
    .await
    .map_err(|e| {
        tracing::warn!("transparency proof generation failed: {:?}", e);
    })
    .ok()
    .flatten();

    Ok(Json(FetchPrekeysResponse {
        identity_key: hex::encode(&row.0),
        identity_dh_key: hex::encode(&row.1),
        signed_prekey: hex::encode(&row.2),
        signed_prekey_sig: hex::encode(&row.3),
        signed_prekey_id: row.4,
        pq_prekey: row.5.as_ref().map(hex::encode),
        pq_prekey_sig: row.6.as_ref().map(hex::encode),
        pq_prekey_id: row.7,
        one_time_prekey: otpk.as_ref().map(|(_, pk)| hex::encode(pk)),
        one_time_prekey_id: otpk.as_ref().map(|(id, _)| *id),
        transparency,
    }))
}

/// GET /v1/transparency/sth
/// Return the current Signed Tree Head.
#[derive(Serialize)]
pub struct SthResponse {
    pub sth: SignedTreeHead,
    pub server_public_key: String,
}

pub async fn get_sth(
    State(state): State<AppState>,
) -> Result<Json<SthResponse>, ApiError> {
    let leaf_hashes = load_all_leaf_hashes(&state).await?;
    let root = transparency::compute_root(&leaf_hashes);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut sth = SignedTreeHead {
        tree_size: leaf_hashes.len() as u64,
        root_hash: root,
        timestamp: now,
        signature: vec![],
    };
    sth.signature = state.transparency_key.sign(&sth.signable_bytes());

    Ok(Json(SthResponse {
        sth,
        server_public_key: hex::encode(state.transparency_key.public_key),
    }))
}

/// GET /v1/transparency/proof/:device_id
/// Return inclusion proof for a device's latest key.
pub async fn get_transparency_proof(
    State(state): State<AppState>,
    Path(device_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<TransparencyProofBundle>, ApiError> {
    // Require Ed25519 authentication (NEW-03)
    let path = format!("/v1/transparency/proof/{}", device_id);
    let _requester = authenticate_device(&headers, "GET", &path, &state.db).await?;

    let client_tree_size: Option<u64> = headers
        .get("x-kt-tree-size")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    let proof = build_transparency_proof(&state, device_id, client_tree_size)
        .await?
        .ok_or_else(|| ApiError::NotFound("no transparency log entry for device".into()))?;

    Ok(Json(proof))
}

/// GET /v1/keys/prekey-count
/// Returns the number of remaining one-time prekeys for the authenticated device.
#[derive(Serialize)]
pub struct PrekeyCountResponse {
    pub count: i64,
}

pub async fn prekey_count(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PrekeyCountResponse>, ApiError> {
    let device_id = authenticate_device(
        &headers,
        "GET",
        "/v1/keys/prekey-count",
        &state.db,
    )
    .await?;

    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM onetime_prekeys WHERE device_id = $1",
    )
    .bind(device_id)
    .fetch_one(&state.db)
    .await?;

    Ok(Json(PrekeyCountResponse { count }))
}

/// POST /v1/keys/upload-otps
/// Upload additional one-time prekeys (up to 200). Authenticated.
#[derive(Deserialize)]
pub struct UploadOtpsRequest {
    pub one_time_prekeys: Vec<OneTimePrekey>,
}

#[derive(Serialize)]
pub struct UploadOtpsResponse {
    pub uploaded: usize,
}

pub async fn upload_additional_otps(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<UploadOtpsRequest>,
) -> Result<Json<UploadOtpsResponse>, ApiError> {
    let device_id = authenticate_device(
        &headers,
        "POST",
        "/v1/keys/upload-otps",
        &state.db,
    )
    .await?;

    if req.one_time_prekeys.len() > 200 {
        return Err(ApiError::BadRequest("max 200 prekeys per upload".into()));
    }

    let mut uploaded = 0;
    for otpk in &req.one_time_prekeys {
        let pk = hex::decode(&otpk.public_key)
            .map_err(|_| ApiError::BadRequest("invalid one_time_prekey hex".into()))?;
        let result = sqlx::query(
            r#"
            INSERT INTO onetime_prekeys (device_id, key_id, public_key)
            VALUES ($1, $2, $3)
            ON CONFLICT (device_id, key_id) DO NOTHING
            "#,
        )
        .bind(device_id)
        .bind(otpk.key_id)
        .bind(&pk)
        .execute(&state.db)
        .await?;
        uploaded += result.rows_affected() as usize;
    }

    tracing::info!("device {} uploaded {} additional OTPs", device_id, uploaded);

    Ok(Json(UploadOtpsResponse { uploaded }))
}

// ─── Internal helpers ───

/// Build a full transparency proof bundle for a device.
async fn build_transparency_proof(
    state: &AppState,
    device_id: Uuid,
    client_tree_size: Option<u64>,
) -> Result<Option<TransparencyProofBundle>, ApiError> {
    // Load all transparency log entries
    let rows: Vec<(i64, Uuid, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>)> =
        sqlx::query_as(
            r#"
            SELECT sequence_id, device_id,
                   identity_key, identity_dh_key, signed_prekey, pq_prekey_hash
            FROM key_transparency_log
            ORDER BY sequence_id ASC
            "#
        )
        .fetch_all(&state.db)
        .await?;

    if rows.is_empty() {
        return Ok(None);
    }

    // Build leaves and compute hashes
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut leaves: Vec<TransparencyLeaf> = Vec::with_capacity(rows.len());
    let mut leaf_hashes: Vec<[u8; 32]> = Vec::with_capacity(rows.len());
    let mut target_index: Option<usize> = None;

    for (i, (seq_id, dev_id, ik, idk, spk, pqh)) in rows.iter().enumerate() {
        let leaf = TransparencyLeaf {
            device_id: dev_id.as_bytes().to_vec(),
            identity_key: ik.clone().unwrap_or_default(),
            identity_dh_key: idk.clone().unwrap_or_default(),
            signed_prekey: spk.clone().unwrap_or_default(),
            pq_prekey_hash: pqh.clone().unwrap_or_default(),
            timestamp: now,
            sequence_id: *seq_id,
        };
        leaf_hashes.push(leaf.hash());
        leaves.push(leaf);

        // Find the latest entry for the target device
        if *dev_id == device_id {
            target_index = Some(i);
        }
    }

    let target_idx = match target_index {
        Some(i) => i,
        None => return Ok(None),
    };

    // Compute root and sign
    let root = transparency::compute_root(&leaf_hashes);

    let mut sth = SignedTreeHead {
        tree_size: leaf_hashes.len() as u64,
        root_hash: root,
        timestamp: now,
        signature: vec![],
    };
    sth.signature = state.transparency_key.sign(&sth.signable_bytes());

    // Generate inclusion proof
    let proof_hashes = transparency::generate_inclusion_proof(&leaf_hashes, target_idx as u64);
    let inclusion_proof = InclusionProof {
        leaf_index: target_idx as u64,
        tree_size: leaf_hashes.len() as u64,
        proof_hashes,
    };

    // Generate consistency proof if client has a previous tree size
    let consistency_proof = client_tree_size.and_then(|old_size| {
        if old_size > 0 && old_size < leaf_hashes.len() as u64 {
            let proof_hashes = transparency::generate_consistency_proof(
                &leaf_hashes,
                old_size,
                leaf_hashes.len() as u64,
            );
            Some(ConsistencyProof {
                old_size,
                new_size: leaf_hashes.len() as u64,
                proof_hashes,
            })
        } else {
            None
        }
    });

    Ok(Some(TransparencyProofBundle {
        sth,
        inclusion_proof,
        leaf: leaves[target_idx].clone(),
        consistency_proof,
    }))
}

/// Load all leaf hashes from the transparency log.
async fn load_all_leaf_hashes(state: &AppState) -> Result<Vec<[u8; 32]>, ApiError> {
    let rows: Vec<(i64, Uuid, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>)> =
        sqlx::query_as(
            r#"
            SELECT sequence_id, device_id,
                   identity_key, identity_dh_key, signed_prekey, pq_prekey_hash
            FROM key_transparency_log
            ORDER BY sequence_id ASC
            "#
        )
        .fetch_all(&state.db)
        .await?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let hashes: Vec<[u8; 32]> = rows
        .iter()
        .map(|(seq_id, dev_id, ik, idk, spk, pqh)| {
            TransparencyLeaf {
                device_id: dev_id.as_bytes().to_vec(),
                identity_key: ik.clone().unwrap_or_default(),
                identity_dh_key: idk.clone().unwrap_or_default(),
                signed_prekey: spk.clone().unwrap_or_default(),
                pq_prekey_hash: pqh.clone().unwrap_or_default(),
                timestamp: now,
                sequence_id: *seq_id,
            }
            .hash()
        })
        .collect();

    Ok(hashes)
}

fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}
