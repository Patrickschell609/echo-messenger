//! Wire protocol: serialization formats for network messages.

use serde::{Deserialize, Serialize};

use crate::types::*;

/// Client → Server messages
#[derive(Serialize, Deserialize)]
pub enum ClientMessage {
    /// Register a new account
    Register {
        phone_hash: [u8; 32],
        verification_code: String,
    },

    /// Upload prekey bundle
    UploadPrekeys {
        identity_key: IdentityPublicKey,
        signed_prekey: PublicKey,
        signed_prekey_signature: Vec<u8>,
        signed_prekey_id: u32,
        pq_prekey: PqPublicKey,
        pq_prekey_signature: Vec<u8>,
        pq_prekey_id: u32,
        one_time_prekeys: Vec<(u32, PublicKey)>,
    },

    /// Fetch recipient's prekey bundle
    FetchPrekeys {
        recipient_device_id: DeviceId,
    },

    /// Send a sealed message (anonymous - no auth header)
    SendMessage {
        recipient_device_id: DeviceId,
        envelope: SealedEnvelope,
    },

    /// Receive pending messages
    ReceiveMessages,

    /// Acknowledge message receipt
    AckMessage {
        message_id: u64,
    },
}

/// Server → Client messages
#[derive(Serialize, Deserialize)]
pub enum ServerMessage {
    /// Registration success
    Registered {
        device_id: DeviceId,
    },

    /// Prekey bundle response
    PrekeyBundle(PrekeyBundle),

    /// Message accepted
    MessageSent {
        timestamp: u64,
    },

    /// Incoming messages
    Messages {
        envelopes: Vec<QueuedMessage>,
    },

    /// Error
    Error {
        code: u32,
        message: String,
    },
}

/// Message in the server queue
#[derive(Serialize, Deserialize)]
pub struct QueuedMessage {
    pub id: u64,
    pub envelope: SealedEnvelope,
    pub queued_at: u64,
}
