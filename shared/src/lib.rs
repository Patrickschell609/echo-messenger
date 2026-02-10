//! # echo-crypto
//!
//! Triple Ratchet (TR3) cryptographic core for ECHO Messenger.
//!
//! ## Architecture
//!
//! ```text
//! Layer 3 (Epoch Ratchet): ML-KEM-1024 post-quantum KEM
//!   └─ Ratchets every 100 messages or 24 hours
//! Layer 2 (DH Ratchet): X25519 ECDH
//!   └─ Ratchets every reply turn
//! Layer 1 (Symmetric Ratchet): HKDF-SHA256 chain
//!   └─ Ratchets every message
//! ```

pub mod crypto;
pub mod ratchet;
pub mod sealed_sender;
pub mod group;
pub mod protocol;
pub mod error;
pub mod types;
pub mod transparency;
pub mod ffi_api;

pub use error::EchoError;
pub use types::*;
