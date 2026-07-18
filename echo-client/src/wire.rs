use serde::{Deserialize, Serialize};

/// Magic prefix to identify media content in encrypted payload.
/// Regular text messages are raw UTF-8. Media messages start with this prefix
/// followed by bincode-serialized MediaContent.
pub const MEDIA_MAGIC: &[u8; 4] = b"\x00ECM";

/// Media content embedded in the encrypted payload.
#[derive(Serialize, Deserialize, Clone)]
pub struct MediaContent {
    pub mime_type: String,
    pub filename: String,
    pub data: Vec<u8>,
}

impl MediaContent {
    /// Encode media content with magic prefix for the ratchet plaintext.
    pub fn encode(&self) -> Vec<u8> {
        let serialized = bincode::serialize(self).expect("MediaContent serialize");
        let mut out = Vec::with_capacity(4 + serialized.len());
        out.extend_from_slice(MEDIA_MAGIC);
        out.extend_from_slice(&serialized);
        out
    }

    /// Try to decode from ratchet plaintext. Returns None if not a media message.
    pub fn decode(plaintext: &[u8]) -> Option<Self> {
        if plaintext.len() < 4 || &plaintext[..4] != MEDIA_MAGIC {
            return None;
        }
        bincode::deserialize(&plaintext[4..]).ok()
    }
}

/// Magic prefix to identify sender key distribution in pairwise messages.
/// When a pairwise 1:1 plaintext starts with this prefix, it carries a
/// bincode-serialized SenderKeyDistribution instead of chat text.
pub const SKD_MAGIC: &[u8; 4] = b"\x00SKD";

/// Encode a SenderKeyDistribution for embedding in a pairwise message.
pub fn encode_skd(skd: &echo_crypto::group::SenderKeyDistribution) -> Vec<u8> {
    let serialized = bincode::serialize(skd).expect("SKD serialize");
    let mut out = Vec::with_capacity(4 + serialized.len());
    out.extend_from_slice(SKD_MAGIC);
    out.extend_from_slice(&serialized);
    out
}

/// Try to decode a SenderKeyDistribution from pairwise plaintext.
/// Returns None if not an SKD message.
pub fn decode_skd(plaintext: &[u8]) -> Option<echo_crypto::group::SenderKeyDistribution> {
    if plaintext.len() < 4 || &plaintext[..4] != SKD_MAGIC {
        return None;
    }
    bincode::deserialize(&plaintext[4..]).ok()
}

/// Magic prefix for control messages (auto-delete timer, edit, delete).
pub const CTRL_MAGIC: &[u8; 4] = b"\x00CTL";

/// Control messages sent through the encrypted ratchet.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ControlMessage {
    /// Session initiation handshake (no visible message, just establishes the session).
    SessionInit,
    /// Set auto-delete timer for the conversation (0 = off).
    SetTimer { duration_secs: u64 },
    /// Edit a previously sent message.
    EditMessage {
        sender_msg_id: String,
        original_timestamp: u64,
        new_text: String,
    },
    /// Delete a previously sent message.
    DeleteMessage {
        sender_msg_id: String,
        original_timestamp: u64,
    },
}

/// Per-conversation settings stored in vault.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ConversationSettings {
    pub auto_delete_secs: u64,
}

/// Encode a control message for embedding in a pairwise message.
pub fn encode_ctrl(msg: &ControlMessage) -> Vec<u8> {
    let serialized = bincode::serialize(msg).expect("ControlMessage serialize");
    let mut out = Vec::with_capacity(4 + serialized.len());
    out.extend_from_slice(CTRL_MAGIC);
    out.extend_from_slice(&serialized);
    out
}

/// Try to decode a control message from pairwise plaintext.
/// Returns None if not a control message.
pub fn decode_ctrl(plaintext: &[u8]) -> Option<ControlMessage> {
    if plaintext.len() < 4 || &plaintext[..4] != CTRL_MAGIC {
        return None;
    }
    bincode::deserialize(&plaintext[4..]).ok()
}

/// Wire message format — first message includes X4DH init data.
#[derive(Serialize, Deserialize)]
pub enum WireMessage {
    /// First message in a session: includes X4DH parameters so recipient can establish.
    PreKey {
        /// Alice's Ed25519 identity public key
        sender_identity_key: Vec<u8>,
        /// Alice's X25519 identity DH public key
        sender_identity_dh_key: Vec<u8>,
        /// Ed25519 signature binding identity_dh_key to identity_key (C4)
        #[serde(default)]
        sender_identity_dh_signature: Vec<u8>,
        /// Alice's ML-DSA-87 identity public key (post-quantum half of the hybrid identity)
        #[serde(default)]
        sender_ml_dsa_identity_key: Vec<u8>,
        /// ML-DSA-87 signature binding identity_dh_key to identity (C4, PQ half)
        #[serde(default)]
        sender_identity_dh_ml_dsa_signature: Vec<u8>,
        /// Ephemeral X25519 public key
        ephemeral_public: Vec<u8>,
        /// PQ KEM ciphertext
        pq_ciphertext: Vec<u8>,
        /// Which one-time prekey was consumed (if any)
        used_one_time_prekey_id: Option<u32>,
        /// The encrypted ratchet message
        ratchet_header: Vec<u8>,
        encrypted_header: Vec<u8>,
        ciphertext: Vec<u8>,
    },
    /// Subsequent messages: session already established.
    Normal {
        ratchet_header: Vec<u8>,
        encrypted_header: Vec<u8>,
        ciphertext: Vec<u8>,
    },
}
