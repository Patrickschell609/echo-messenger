//! HTTP client for talking to the ECHO server.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::identity::KeyMaterial;

/// Ed25519 auth credentials for signing requests.
pub struct AuthCredentials {
    pub device_id: Uuid,
    pub signing_key: ed25519_dalek::SigningKey,
}

pub struct HttpClient {
    base_url: String,
    client: reqwest::Client,
    auth: Option<AuthCredentials>,
}

impl HttpClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
            auth: None,
        }
    }

    /// Create an authenticated client with Ed25519 signing.
    pub fn with_auth(base_url: &str, device_id: Uuid, ed25519_private: &[u8; 32]) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(ed25519_private);
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
            auth: Some(AuthCredentials {
                device_id,
                signing_key,
            }),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Sign a request with Ed25519: device_id || timestamp || method || path
    fn sign_request(
        &self,
        method: &str,
        path: &str,
    ) -> Option<(String, String, String)> {
        let auth = self.auth.as_ref()?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let timestamp_str = timestamp.to_string();
        let device_id_str = auth.device_id.to_string();

        let mut message = Vec::new();
        message.extend_from_slice(device_id_str.as_bytes());
        message.extend_from_slice(timestamp_str.as_bytes());
        message.extend_from_slice(method.as_bytes());
        message.extend_from_slice(path.as_bytes());

        use ed25519_dalek::Signer;
        let signature = auth.signing_key.sign(&message);
        let sig_hex = hex::encode(signature.to_bytes());

        Some((device_id_str, timestamp_str, sig_hex))
    }

    /// Add auth headers to a request builder if credentials are available.
    fn add_auth_headers(
        &self,
        mut req: reqwest::RequestBuilder,
        method: &str,
        path: &str,
    ) -> reqwest::RequestBuilder {
        if let Some((device_id, timestamp, signature)) = self.sign_request(method, path) {
            req = req
                .header("x-device-id", device_id)
                .header("x-auth-timestamp", timestamp)
                .header("x-auth-signature", signature);
        }
        req
    }

    /// POST /v1/invites/generate (authenticated) — returns list of invite code hex strings
    pub async fn generate_invites(&self, count: u32) -> Result<Vec<String>> {
        #[derive(Serialize)]
        struct Req {
            count: u32,
        }
        #[derive(Deserialize)]
        struct Resp {
            codes: Vec<String>,
        }

        let path = "/v1/invites/generate";
        let mut req = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .json(&Req { count });

        req = self.add_auth_headers(req, "POST", path);

        let resp = req.send().await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("generate_invites failed ({}): {}", status, body));
        }

        let data: Resp = resp.json().await?;
        Ok(data.codes)
    }

    /// POST /v1/invites/redeem (unauthenticated) — returns (account_id, auth_nonce)
    pub async fn redeem_invite(&self, invite_code: &str) -> Result<(Uuid, String)> {
        #[derive(Serialize)]
        struct Req {
            invite_code: String,
        }
        #[derive(Deserialize)]
        struct Resp {
            account_id: Uuid,
            auth_nonce: String,
        }

        let resp = self
            .client
            .post(format!("{}/v1/invites/redeem", self.base_url))
            .json(&Req {
                invite_code: invite_code.to_string(),
            })
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("redeem_invite failed ({}): {}", status, body));
        }

        let data: Resp = resp.json().await?;
        Ok((data.account_id, data.auth_nonce))
    }

    /// GET /v1/keys/prekey-count (authenticated) — returns remaining OTP count
    pub async fn prekey_count(&self) -> Result<i64> {
        #[derive(Deserialize)]
        struct Resp {
            count: i64,
        }

        let path = "/v1/keys/prekey-count";
        let mut req = self.client.get(format!("{}{}", self.base_url, path));
        req = self.add_auth_headers(req, "GET", path);

        let resp = req.send().await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("prekey_count failed ({}): {}", status, body));
        }

        let data: Resp = resp.json().await?;
        Ok(data.count)
    }

    /// POST /v1/keys/upload-otps (authenticated) — upload additional one-time prekeys
    pub async fn upload_additional_otps(&self, otps: &[(u32, String)]) -> Result<()> {
        #[derive(Serialize)]
        struct OtpkReq {
            key_id: i32,
            public_key: String,
        }
        #[derive(Serialize)]
        struct Req {
            one_time_prekeys: Vec<OtpkReq>,
        }

        let otpks: Vec<OtpkReq> = otps
            .iter()
            .map(|(id, pk)| OtpkReq {
                key_id: *id as i32,
                public_key: pk.clone(),
            })
            .collect();

        let path = "/v1/keys/upload-otps";
        let mut req = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .json(&Req {
                one_time_prekeys: otpks,
            });

        req = self.add_auth_headers(req, "POST", path);

        let resp = req.send().await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("upload_additional_otps failed ({}): {}", status, body));
        }

        Ok(())
    }

    /// POST /v1/register — returns (account_id, auth_nonce)
    pub async fn register(&self, phone_hash_hex: &str) -> Result<(Uuid, String)> {
        #[derive(Serialize)]
        struct Req {
            phone_hash: String,
        }
        #[derive(Deserialize)]
        struct Resp {
            account_id: Uuid,
            auth_nonce: String,
        }

        let resp = self
            .client
            .post(format!("{}/v1/register", self.base_url))
            .json(&Req {
                phone_hash: phone_hash_hex.to_string(),
            })
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("register failed ({}): {}", status, body));
        }

        let data: Resp = resp.json().await?;
        Ok((data.account_id, data.auth_nonce))
    }

    /// POST /v1/keys/upload — requires auth_nonce (for new device) + Ed25519 signature
    /// Returns (device_id, optional sender_cert_bytes)
    pub async fn upload_prekeys(
        &self,
        account_id: Uuid,
        keys: &KeyMaterial,
        auth_nonce: Option<&str>,
    ) -> Result<(Uuid, Option<Vec<u8>>)> {
        #[derive(Serialize)]
        struct OtpkReq {
            key_id: i32,
            public_key: String,
        }
        #[derive(Serialize)]
        struct Req {
            account_id: Uuid,
            identity_key: String,
            identity_dh_key: String,
            signed_prekey: String,
            signed_prekey_sig: String,
            signed_prekey_id: i32,
            pq_prekey: Option<String>,
            pq_prekey_sig: Option<String>,
            pq_prekey_id: Option<i32>,
            one_time_prekeys: Vec<OtpkReq>,
            auth_nonce: Option<String>,
            auth_signature: Option<String>,
        }
        #[derive(Deserialize)]
        struct Resp {
            device_id: Uuid,
            sender_cert: Option<String>,
        }

        let otpks: Vec<OtpkReq> = keys
            .one_time_prekeys
            .iter()
            .map(|(id, kp)| OtpkReq {
                key_id: *id as i32,
                public_key: hex::encode(&kp.public_key().0),
            })
            .collect();

        // Sign: "echo-key-upload:" || account_id || identity_key_bytes
        let identity_key_bytes = keys.identity_ed.public_key().0;
        let mut sign_msg = Vec::new();
        sign_msg.extend_from_slice(b"echo-key-upload:");
        sign_msg.extend_from_slice(account_id.as_bytes());
        sign_msg.extend_from_slice(&identity_key_bytes);

        use ed25519_dalek::Signer;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&keys.identity_ed.private_key_bytes().0);
        let sig = signing_key.sign(&sign_msg);
        let auth_signature = hex::encode(sig.to_bytes());

        let req = Req {
            account_id,
            identity_key: hex::encode(&identity_key_bytes),
            identity_dh_key: hex::encode(&keys.identity_dh.public_key().0),
            signed_prekey: hex::encode(&keys.signed_prekey.public_key().0),
            signed_prekey_sig: hex::encode(&keys.signed_prekey_sig),
            signed_prekey_id: keys.signed_prekey_id as i32,
            pq_prekey: Some(hex::encode(&keys.pq_pk.0)),
            pq_prekey_sig: Some(hex::encode(&keys.pq_prekey_sig)),
            pq_prekey_id: Some(keys.pq_prekey_id as i32),
            one_time_prekeys: otpks,
            auth_nonce: auth_nonce.map(|s| s.to_string()),
            auth_signature: Some(auth_signature),
        };

        let resp = self
            .client
            .post(format!("{}/v1/keys/upload", self.base_url))
            .json(&req)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("upload_prekeys failed ({}): {}", status, body));
        }

        let data: Resp = resp.json().await?;
        let cert_bytes = data.sender_cert
            .map(|h| hex::decode(h))
            .transpose()
            .map_err(|_| anyhow!("invalid sender_cert hex in response"))?;
        Ok((data.device_id, cert_bytes))
    }

    /// GET /v1/keys/:device_id (authenticated)
    pub async fn fetch_prekeys(
        &self,
        our_device_id: Uuid,
        target_device_id: Uuid,
        last_tree_size: Option<u64>,
    ) -> Result<PrekeyBundleResponse> {
        let path = format!("/v1/keys/{}", target_device_id);
        let mut req = self
            .client
            .get(format!("{}{}", self.base_url, path));

        // Add auth headers if available, otherwise fall back to plain header
        if self.auth.is_some() {
            req = self.add_auth_headers(req, "GET", &path);
        } else {
            req = req.header("x-device-id", our_device_id.to_string());
        }

        if let Some(size) = last_tree_size {
            req = req.header("x-kt-tree-size", size.to_string());
        }

        let resp = req.send().await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("fetch_prekeys failed ({}): {}", status, body));
        }

        let data: PrekeyBundleResponse = resp.json().await?;
        Ok(data)
    }

    /// GET /v1/transparency/proof/:device_id
    pub async fn fetch_transparency_proof(
        &self,
        device_id: Uuid,
        last_tree_size: Option<u64>,
    ) -> Result<echo_crypto::transparency::TransparencyProofBundle> {
        let mut req = self
            .client
            .get(format!("{}/v1/transparency/proof/{}", self.base_url, device_id));

        if let Some(size) = last_tree_size {
            req = req.header("x-kt-tree-size", size.to_string());
        }

        let resp = req.send().await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("fetch_transparency_proof failed ({}): {}", status, body));
        }

        let data = resp.json().await?;
        Ok(data)
    }

    /// GET /v1/transparency/sth
    pub async fn fetch_sth(&self) -> Result<SthResponse> {
        let resp = self
            .client
            .get(format!("{}/v1/transparency/sth", self.base_url))
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("fetch_sth failed ({}): {}", status, body));
        }

        let data: SthResponse = resp.json().await?;
        Ok(data)
    }

    /// POST /v1/profile/update (authenticated) — set display name and/or bio
    pub async fn update_profile(
        &self,
        display_name: Option<&str>,
        bio: Option<&str>,
    ) -> Result<ProfileResponse> {
        #[derive(Serialize)]
        struct Req {
            display_name: Option<String>,
            bio: Option<String>,
        }

        let path = "/v1/profile/update";
        let mut req = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .json(&Req {
                display_name: display_name.map(|s| s.to_string()),
                bio: bio.map(|s| s.to_string()),
            });

        req = self.add_auth_headers(req, "POST", path);

        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("update_profile failed ({}): {}", status, body));
        }

        let data: ProfileResponse = resp.json().await?;
        Ok(data)
    }

    /// GET /v1/profile/{device_id} (authenticated) — fetch profile for a device
    pub async fn fetch_profile(&self, target_device_id: Uuid) -> Result<ProfileResponse> {
        let path = format!("/v1/profile/{}", target_device_id);
        let mut req = self.client.get(format!("{}{}", self.base_url, path));
        req = self.add_auth_headers(req, "GET", &path);

        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("fetch_profile failed ({}): {}", status, body));
        }

        let data: ProfileResponse = resp.json().await?;
        Ok(data)
    }

    /// POST /v1/messages/send (UNAUTHENTICATED — sealed sender)
    pub async fn send_message(&self, recipient_device_id: Uuid, envelope_bytes: &[u8]) -> Result<()> {
        #[derive(Serialize)]
        struct Req {
            recipient_device_id: Uuid,
            envelope: String,
        }

        let resp = self
            .client
            .post(format!("{}/v1/messages/send", self.base_url))
            .json(&Req {
                recipient_device_id,
                envelope: hex::encode(envelope_bytes),
            })
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("send failed ({}): {}", status, body));
        }

        Ok(())
    }

    /// GET /v1/messages/receive (authenticated)
    pub async fn receive_messages(&self, device_id: Uuid) -> Result<Vec<QueuedMessage>> {
        #[derive(Deserialize)]
        struct Resp {
            messages: Vec<QueuedMessage>,
        }

        let path = "/v1/messages/receive";
        let mut req = self
            .client
            .get(format!("{}{}", self.base_url, path));

        if self.auth.is_some() {
            req = self.add_auth_headers(req, "GET", path);
        } else {
            req = req.header("x-device-id", device_id.to_string());
        }

        let resp = req.send().await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("receive failed ({}): {}", status, body));
        }

        let data: Resp = resp.json().await?;
        Ok(data.messages)
    }

    /// POST /v1/messages/ack (authenticated)
    pub async fn ack_messages(&self, device_id: Uuid, message_ids: &[i64]) -> Result<()> {
        #[derive(Serialize)]
        struct Req {
            message_ids: Vec<i64>,
        }

        let path = "/v1/messages/ack";
        let mut req = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .json(&Req {
                message_ids: message_ids.to_vec(),
            });

        if self.auth.is_some() {
            req = self.add_auth_headers(req, "POST", path);
        } else {
            req = req.header("x-device-id", device_id.to_string());
        }

        let resp = req.send().await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("ack failed ({}): {}", status, body));
        }

        Ok(())
    }
}

/// Server response for prekey bundle fetch.
#[derive(Deserialize)]
pub struct PrekeyBundleResponse {
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
    pub transparency: Option<echo_crypto::transparency::TransparencyProofBundle>,
}

impl PrekeyBundleResponse {
    pub fn to_prekey_bundle(&self) -> Result<echo_crypto::PrekeyBundle> {
        let identity_key_bytes = hex::decode(&self.identity_key)?;
        let identity_dh_key_bytes = hex::decode(&self.identity_dh_key)?;
        let signed_prekey_bytes = hex::decode(&self.signed_prekey)?;
        let signed_prekey_sig = hex::decode(&self.signed_prekey_sig)?;
        let pq_prekey_bytes = self
            .pq_prekey
            .as_ref()
            .map(|h| hex::decode(h))
            .transpose()?
            .ok_or_else(|| anyhow::anyhow!("missing pq_prekey"))?;
        let pq_prekey_sig = self
            .pq_prekey_sig
            .as_ref()
            .map(|h| hex::decode(h))
            .transpose()?
            .ok_or_else(|| anyhow::anyhow!("missing pq_prekey_sig"))?;
        let one_time_prekey = self
            .one_time_prekey
            .as_ref()
            .map(|h| hex::decode(h))
            .transpose()?;

        let mut ik = [0u8; 32];
        let mut idk = [0u8; 32];
        let mut spk = [0u8; 32];
        ik.copy_from_slice(&identity_key_bytes);
        idk.copy_from_slice(&identity_dh_key_bytes);
        spk.copy_from_slice(&signed_prekey_bytes);

        let otpk = one_time_prekey.map(|b| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            echo_crypto::PublicKey(arr)
        });

        Ok(echo_crypto::PrekeyBundle {
            identity_key: echo_crypto::IdentityPublicKey(ik),
            identity_dh_key: echo_crypto::PublicKey(idk),
            signed_prekey: echo_crypto::PublicKey(spk),
            signed_prekey_signature: signed_prekey_sig,
            signed_prekey_id: self.signed_prekey_id as u32,
            pq_prekey: echo_crypto::PqPublicKey(pq_prekey_bytes),
            pq_prekey_signature: pq_prekey_sig,
            pq_prekey_id: self.pq_prekey_id.unwrap_or(1) as u32,
            one_time_prekey: otpk,
            one_time_prekey_id: self.one_time_prekey_id.map(|id| id as u32),
        })
    }
}

#[derive(Deserialize, Clone)]
pub struct QueuedMessage {
    pub id: i64,
    pub envelope: String,
    pub queued_at: i64,
}

/// Response from /v1/profile endpoints.
#[derive(Deserialize, Clone, Serialize)]
pub struct ProfileResponse {
    pub device_id: String,
    pub display_name: Option<String>,
    pub bio: Option<String>,
}

/// Response from /v1/transparency/sth
#[derive(Deserialize)]
pub struct SthResponse {
    pub sth: echo_crypto::transparency::SignedTreeHead,
    pub server_public_key: String,
}

// ─── Group API ───

#[derive(Deserialize, Clone, Serialize)]
pub struct GroupResponse {
    pub group_id: String,
    pub name: String,
    pub member_count: i64,
}

#[derive(Deserialize, Clone, Serialize)]
pub struct GroupQueuedMessage {
    pub id: i64,
    pub sender_device_id: String,
    pub payload: String,
    pub queued_at: i64,
}

#[derive(Deserialize, Clone, Serialize)]
pub struct GroupMemberInfo {
    pub device_id: String,
    pub role: i16,
}

impl HttpClient {
    /// POST /v1/groups — create a group (authenticated)
    pub async fn create_group(
        &self,
        name: &str,
        member_device_ids: &[Uuid],
    ) -> Result<GroupResponse> {
        #[derive(Serialize)]
        struct Req {
            name: String,
            member_device_ids: Vec<Uuid>,
        }

        let path = "/v1/groups";
        let mut req = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .json(&Req {
                name: name.to_string(),
                member_device_ids: member_device_ids.to_vec(),
            });
        req = self.add_auth_headers(req, "POST", path);

        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("create_group failed ({}): {}", status, body));
        }
        let data: GroupResponse = resp.json().await?;
        Ok(data)
    }

    /// GET /v1/groups — list groups (authenticated)
    pub async fn list_groups(&self) -> Result<Vec<GroupResponse>> {
        let path = "/v1/groups";
        let mut req = self.client.get(format!("{}{}", self.base_url, path));
        req = self.add_auth_headers(req, "GET", path);

        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("list_groups failed ({}): {}", status, body));
        }
        let data: Vec<GroupResponse> = resp.json().await?;
        Ok(data)
    }

    /// POST /v1/groups/{id}/send — send group message (authenticated)
    pub async fn send_group_message(&self, group_id: Uuid, payload: &[u8]) -> Result<i64> {
        #[derive(Serialize)]
        struct Req {
            payload: String,
        }
        #[derive(Deserialize)]
        struct Resp {
            id: i64,
        }

        let path = format!("/v1/groups/{}/send", group_id);
        let mut req = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .json(&Req {
                payload: hex::encode(payload),
            });
        req = self.add_auth_headers(req, "POST", &path);

        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("send_group_message failed ({}): {}", status, body));
        }
        let data: Resp = resp.json().await?;
        Ok(data.id)
    }

    /// GET /v1/groups/{id}/messages — fetch group messages (authenticated)
    pub async fn receive_group_messages(&self, group_id: Uuid) -> Result<Vec<GroupQueuedMessage>> {
        let path = format!("/v1/groups/{}/messages", group_id);
        let mut req = self.client.get(format!("{}{}", self.base_url, path));
        req = self.add_auth_headers(req, "GET", &path);

        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("receive_group_messages failed ({}): {}", status, body));
        }
        let data: Vec<GroupQueuedMessage> = resp.json().await?;
        Ok(data)
    }

    /// GET /v1/groups/{id}/members (authenticated)
    pub async fn get_group_members(&self, group_id: Uuid) -> Result<Vec<GroupMemberInfo>> {
        let path = format!("/v1/groups/{}/members", group_id);
        let mut req = self.client.get(format!("{}{}", self.base_url, path));
        req = self.add_auth_headers(req, "GET", &path);

        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("get_group_members failed ({}): {}", status, body));
        }
        let data: Vec<GroupMemberInfo> = resp.json().await?;
        Ok(data)
    }

    /// POST /v1/groups/{id}/leave (authenticated)
    pub async fn leave_group(&self, group_id: Uuid) -> Result<()> {
        let path = format!("/v1/groups/{}/leave", group_id);
        let mut req = self.client.post(format!("{}{}", self.base_url, path));
        req = self.add_auth_headers(req, "POST", &path);

        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("leave_group failed ({}): {}", status, body));
        }
        Ok(())
    }
}
