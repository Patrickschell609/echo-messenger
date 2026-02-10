//! Triple Ratchet (TR3) protocol implementation.
//!
//! Three layers of ratcheting:
//! - Layer 1: Symmetric chain (HKDF) - every message
//! - Layer 2: DH ratchet (X25519) - every reply turn
//! - Layer 3: Epoch ratchet (ML-KEM-1024) - every N messages or T seconds

pub mod session;
pub mod state;
pub mod x4dh;

pub use session::TripleRatchetSession;
pub use state::RatchetState;
pub use x4dh::X4DH;
