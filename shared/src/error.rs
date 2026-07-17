use thiserror::Error;

#[derive(Error, Debug)]
pub enum EchoError {
    #[error("Invalid key material: {0}")]
    InvalidKey(String),

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Session not found for device: {0}")]
    SessionNotFound(String),

    #[error("Message replay detected: {0}")]
    ReplayDetected(String),

    #[error("Too many skipped messages ({0} > max {1})")]
    TooManySkipped(u32, u32),

    #[error("Ratchet chain exhausted")]
    ChainExhausted,

    #[error("Invalid message format: {0}")]
    InvalidMessage(String),

    #[error("PQ KEM error: {0}")]
    PqKemError(String),

    #[error("PQ signature error: {0}")]
    PqSignError(String),

    #[error("Sealed sender verification failed")]
    SealedSenderFailed,

    #[error("Group epoch mismatch: expected {expected}, got {got}")]
    GroupEpochMismatch { expected: u32, got: u32 },

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

pub type Result<T> = std::result::Result<T, EchoError>;
