//! Encrypted message history — SQLite + AES-256-GCM per-conversation keys.
//!
//! Each message's text is encrypted with a key derived from:
//!   vault master key → HKDF("echo-vault-subkey:history") → HKDF("echo-history-peer:{peer_id}")
//!
//! Schema stores only ciphertext + nonce. No plaintext on disk ever.

use std::path::Path;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct HistoryMessage {
    pub id: i64,
    pub peer_id: String,
    pub text: String,
    pub sent_by_me: bool,
    pub timestamp: u64,
    pub status: u8, // 0=sent, 1=delivered, 2=read
    pub edited: bool,
}

pub struct EncryptedHistory {
    db: rusqlite::Connection,
    history_key: [u8; 32],
}

impl Drop for EncryptedHistory {
    fn drop(&mut self) {
        self.history_key.zeroize();
    }
}

impl EncryptedHistory {
    /// Open (or create) the history database.
    pub fn open(db_path: &Path, history_key: [u8; 32]) -> Result<Self> {
        let db = rusqlite::Connection::open(db_path)?;
        db.execute_batch("PRAGMA journal_mode=WAL;")?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                msg_id TEXT UNIQUE,
                peer_id TEXT NOT NULL,
                ciphertext BLOB NOT NULL,
                nonce BLOB NOT NULL,
                sent_by_me INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                status INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_messages_peer_ts ON messages(peer_id, timestamp);",
        )?;
        // Migration: add status column if missing (existing databases)
        let _ = db.execute_batch("ALTER TABLE messages ADD COLUMN status INTEGER DEFAULT 0;");
        // Migration: add expires_at and edited columns for auto-delete and edit support
        let _ = db.execute_batch("ALTER TABLE messages ADD COLUMN expires_at INTEGER;");
        let _ = db.execute_batch("ALTER TABLE messages ADD COLUMN edited INTEGER DEFAULT 0;");
        let _ = db.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_messages_expires ON messages(expires_at) WHERE expires_at IS NOT NULL;",
        );
        Ok(Self { db, history_key })
    }

    /// Derive per-conversation encryption key from history root key + peer_id.
    fn derive_peer_key(&self, peer_id: &str) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.history_key);
        let info = format!("echo-history-peer:{}", peer_id);
        let mut key = [0u8; 32];
        hk.expand(info.as_bytes(), &mut key)
            .expect("HKDF expand for 32 bytes");
        key
    }

    /// Insert a message into history. Duplicate msg_ids are silently ignored.
    pub fn insert_message(
        &self,
        msg_id: &str,
        peer_id: &str,
        text: &str,
        sent_by_me: bool,
        timestamp: u64,
    ) -> Result<()> {
        let key = self.derive_peer_key(peer_id);
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow!("AES key init: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, text.as_bytes())
            .map_err(|e| anyhow!("encrypt: {}", e))?;

        self.db.execute(
            "INSERT OR IGNORE INTO messages (msg_id, peer_id, ciphertext, nonce, sent_by_me, timestamp) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![msg_id, peer_id, ciphertext, &nonce_bytes[..], sent_by_me as i32, timestamp as i64],
        )?;
        Ok(())
    }

    /// Load messages for a peer, paginated. Returns in chronological order.
    /// Pass `before_timestamp` to load older messages (scroll-to-load-more).
    pub fn load_messages(
        &self,
        peer_id: &str,
        limit: u32,
        before_timestamp: Option<u64>,
    ) -> Result<Vec<HistoryMessage>> {
        let key = self.derive_peer_key(peer_id);
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow!("AES key init: {}", e))?;

        let mut messages = Vec::new();

        if let Some(before) = before_timestamp {
            let mut stmt = self.db.prepare(
                "SELECT id, ciphertext, nonce, sent_by_me, timestamp, COALESCE(status, 0), COALESCE(edited, 0) FROM messages \
                 WHERE peer_id = ?1 AND timestamp < ?2 ORDER BY timestamp DESC LIMIT ?3",
            )?;
            let rows = stmt.query_map(
                rusqlite::params![peer_id, before as i64, limit],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i32>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i32>(5)?,
                        row.get::<_, i32>(6)?,
                    ))
                },
            )?;
            for row in rows {
                let (id, ct, nonce_bytes, sent, ts, status, edited) = row?;
                if let Some(msg) = decrypt_row(&cipher, id, peer_id, ct, nonce_bytes, sent, ts, status, edited) {
                    messages.push(msg);
                }
            }
        } else {
            let mut stmt = self.db.prepare(
                "SELECT id, ciphertext, nonce, sent_by_me, timestamp, COALESCE(status, 0), COALESCE(edited, 0) FROM messages \
                 WHERE peer_id = ?1 ORDER BY timestamp DESC LIMIT ?2",
            )?;
            let rows = stmt.query_map(rusqlite::params![peer_id, limit], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i32>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i32>(5)?,
                    row.get::<_, i32>(6)?,
                ))
            })?;
            for row in rows {
                let (id, ct, nonce_bytes, sent, ts, status, edited) = row?;
                if let Some(msg) = decrypt_row(&cipher, id, peer_id, ct, nonce_bytes, sent, ts, status, edited) {
                    messages.push(msg);
                }
            }
        }

        // Queried DESC for pagination, reverse for chronological order
        messages.reverse();
        Ok(messages)
    }

    /// Count messages for a peer (for badge counts).
    pub fn message_count(&self, peer_id: &str) -> Result<u64> {
        let count: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM messages WHERE peer_id = ?1",
            [peer_id],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    /// Update status of sent messages to a peer up to a timestamp.
    /// Only increases status (sent→delivered→read), never decreases.
    pub fn update_sent_status(
        &self,
        peer_id: &str,
        up_to_timestamp: u64,
        new_status: u8,
    ) -> Result<usize> {
        let changed = self.db.execute(
            "UPDATE messages SET status = ?1 WHERE peer_id = ?2 AND sent_by_me = 1 AND timestamp <= ?3 AND status < ?1",
            rusqlite::params![new_status as i32, peer_id, up_to_timestamp as i64],
        )?;
        Ok(changed)
    }

    /// Get the max timestamp of received messages from a peer (for receipt watermark).
    pub fn max_received_timestamp(&self, peer_id: &str) -> Result<Option<u64>> {
        let result: Option<i64> = self.db.query_row(
            "SELECT MAX(timestamp) FROM messages WHERE peer_id = ?1 AND sent_by_me = 0",
            [peer_id],
            |row| row.get(0),
        )?;
        Ok(result.map(|t| t as u64))
    }

    /// Set message status by msg_id (used when outbox message is sent).
    pub fn set_message_status(&self, msg_id: &str, status: u8) -> Result<()> {
        self.db.execute(
            "UPDATE messages SET status = ?1 WHERE msg_id = ?2",
            rusqlite::params![status as i32, msg_id],
        )?;
        Ok(())
    }

    /// Delete all messages for a peer (when buddy is removed).
    pub fn delete_peer_messages(&self, peer_id: &str) -> Result<()> {
        self.db
            .execute("DELETE FROM messages WHERE peer_id = ?1", [peer_id])?;
        Ok(())
    }

    /// Insert a message with optional expiry timestamp.
    pub fn insert_message_with_expiry(
        &self,
        msg_id: &str,
        peer_id: &str,
        text: &str,
        sent_by_me: bool,
        timestamp: u64,
        expires_at: Option<u64>,
    ) -> Result<()> {
        let key = self.derive_peer_key(peer_id);
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow!("AES key init: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, text.as_bytes())
            .map_err(|e| anyhow!("encrypt: {}", e))?;

        let expires: Option<i64> = expires_at.map(|e| e as i64);

        self.db.execute(
            "INSERT OR IGNORE INTO messages (msg_id, peer_id, ciphertext, nonce, sent_by_me, timestamp, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![msg_id, peer_id, ciphertext, &nonce_bytes[..], sent_by_me as i32, timestamp as i64, expires],
        )?;
        Ok(())
    }

    /// Purge expired messages. Returns count of deleted rows.
    pub fn purge_expired(&self) -> Result<usize> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let count = self.db.execute(
            "DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            [now],
        )?;
        Ok(count)
    }

    /// Set expires_at for all existing messages with a peer.
    /// If duration_secs is 0, clears expires_at (timer off).
    pub fn set_expires_for_peer(&self, peer_id: &str, duration_secs: u64) -> Result<()> {
        if duration_secs == 0 {
            self.db.execute(
                "UPDATE messages SET expires_at = NULL WHERE peer_id = ?1",
                [peer_id],
            )?;
        } else {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let expires = now + duration_secs as i64;
            self.db.execute(
                "UPDATE messages SET expires_at = ?1 WHERE peer_id = ?2 AND expires_at IS NULL",
                rusqlite::params![expires, peer_id],
            )?;
        }
        Ok(())
    }

    /// Edit a message: re-encrypt with new text, set edited=1.
    pub fn edit_message(&self, row_id: i64, peer_id: &str, new_text: &str) -> Result<()> {
        let key = self.derive_peer_key(peer_id);
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow!("AES key init: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, new_text.as_bytes())
            .map_err(|e| anyhow!("encrypt: {}", e))?;

        self.db.execute(
            "UPDATE messages SET ciphertext = ?1, nonce = ?2, edited = 1 WHERE id = ?3",
            rusqlite::params![ciphertext, &nonce_bytes[..], row_id],
        )?;
        Ok(())
    }

    /// Delete a single message by row id.
    pub fn delete_message(&self, row_id: i64) -> Result<()> {
        self.db
            .execute("DELETE FROM messages WHERE id = ?1", [row_id])?;
        Ok(())
    }

    /// Find a message by peer_id and approximate timestamp (within 30s window).
    /// Used for edit/delete matching across devices with different clocks.
    pub fn find_message_by_peer_and_time(
        &self,
        peer_id: &str,
        sent_by_me: bool,
        timestamp: u64,
    ) -> Result<Option<i64>> {
        let ts = timestamp as i64;
        let result = self.db.query_row(
            "SELECT id FROM messages WHERE peer_id = ?1 AND sent_by_me = ?2 \
             AND timestamp BETWEEN ?3 - 30 AND ?3 + 30 \
             ORDER BY ABS(timestamp - ?3) LIMIT 1",
            rusqlite::params![peer_id, sent_by_me as i32, ts],
            |row| row.get::<_, i64>(0),
        );
        match result {
            Ok(id) => Ok(Some(id)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get the msg_id for a row (for event payloads).
    pub fn get_msg_id(&self, row_id: i64) -> Result<Option<String>> {
        let result = self.db.query_row(
            "SELECT msg_id FROM messages WHERE id = ?1",
            [row_id],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(id) => Ok(Some(id)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get message metadata by row id (for edit/delete authorization).
    /// Returns (sent_by_me, timestamp, msg_id) without decrypting content.
    pub fn get_message_info(&self, row_id: i64) -> Result<Option<(bool, u64, String)>> {
        let result = self.db.query_row(
            "SELECT sent_by_me, timestamp, msg_id FROM messages WHERE id = ?1",
            [row_id],
            |row| {
                Ok((
                    row.get::<_, i32>(0)? != 0,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, String>(2)?,
                ))
            },
        );
        match result {
            Ok(info) => Ok(Some(info)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

/// Decrypt a single row from the database.
fn decrypt_row(
    cipher: &Aes256Gcm,
    id: i64,
    peer_id: &str,
    ct: Vec<u8>,
    nonce_bytes: Vec<u8>,
    sent: i32,
    ts: i64,
    status: i32,
    edited: i32,
) -> Option<HistoryMessage> {
    if nonce_bytes.len() != 12 {
        return None;
    }
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ct.as_ref()).ok()?;
    Some(HistoryMessage {
        id,
        peer_id: peer_id.to_string(),
        text: String::from_utf8_lossy(&plaintext).to_string(),
        sent_by_me: sent != 0,
        timestamp: ts as u64,
        status: status as u8,
        edited: edited != 0,
    })
}
