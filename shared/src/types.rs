use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protocol version
pub const PROTOCOL_VERSION: u8 = 1;

/// Max skipped message keys to store per session
pub const MAX_SKIP: u32 = 1000;

/// Messages between PQ epoch ratchets
pub const PQ_RATCHET_INTERVAL: u32 = 100;

/// Seconds between PQ epoch ratchets
pub const PQ_RATCHET_TIME_INTERVAL: u64 = 86400; // 24 hours

/// Padding block size for traffic analysis resistance
pub const PADDING_BLOCK_SIZE: usize = 256;

/// X25519 public key (32 bytes)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey(pub [u8; 32]);

/// X25519 private key (32 bytes) - zeroized on drop
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey(pub [u8; 32]);

/// Ed25519 identity public key
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityPublicKey(pub [u8; 32]);

/// Ed25519 identity private key - zeroized on drop
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct IdentityPrivateKey(pub [u8; 32]);

/// ML-KEM-1024 public key (1568 bytes)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqPublicKey(pub Vec<u8>);

/// ML-KEM-1024 secret key - zeroized on drop
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PqSecretKey(pub Vec<u8>);

/// ML-KEM-1024 ciphertext (1568 bytes)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqCiphertext(pub Vec<u8>);

/// 32-byte symmetric key - zeroized on drop
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey(pub [u8; 32]);

/// Chain key for symmetric ratchet
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ChainKey(pub [u8; 32]);

/// Root key for DH ratchet
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct RootKey(pub [u8; 32]);

/// Message key derived from chain - single use
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct MessageKey(pub [u8; 32]);

/// Header key for encrypted headers
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct HeaderKey(pub [u8; 32]);

/// Device identifier
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub [u8; 16]);

/// Prekey bundle published to server
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrekeyBundle {
    pub identity_key: IdentityPublicKey,
    pub identity_dh_key: PublicKey,              // X25519 identity key for DH operations
    pub signed_prekey: PublicKey,
    pub signed_prekey_signature: Vec<u8>,
    pub signed_prekey_id: u32,
    pub pq_prekey: PqPublicKey,
    pub pq_prekey_signature: Vec<u8>,
    pub pq_prekey_id: u32,
    pub one_time_prekey: Option<PublicKey>,
    pub one_time_prekey_id: Option<u32>,
}

/// Encrypted message envelope (what the server sees)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedEnvelope {
    pub version: u8,
    pub ephemeral_public: PublicKey,
    pub encrypted_payload: Vec<u8>,
}

/// Message header (encrypted inside the envelope)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageHeader {
    pub message_type: MessageType,
    pub dh_public: PublicKey,
    pub dh_ratchet_number: u32,
    pub prev_chain_length: u32,
    pub message_number: u32,
    pub epoch_number: u32,
    pub epoch_ciphertext: Option<PqCiphertext>,
    pub new_epoch_public: Option<PqPublicKey>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum MessageType {
    Prekey,
    Normal,
    PqEpochUpdate,
    KeyRequest,
}
