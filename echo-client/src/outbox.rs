//! Offline outbox — queue encrypted messages for later delivery.
//!
//! Messages are stored as pre-encrypted envelope bytes. The ratchet state
//! was already persisted before queuing (AV-06), so retrying is safe.
//!
//! Constraints:
//! - Max 1000 queued messages (prevent unbounded disk growth)
//! - Entries expire after 7 days (stale messages shouldn't retry)
//! - Separate SQLite DB from history (outbox.db in vault dir)

use std::path::Path;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use rand::RngCore;
use zeroize::Zeroize;

pub struct OutboxQueue {
    db: rusqlite::Connection,
    encryption_key: Option<[u8; 32]>,
}

impl Drop for OutboxQueue {
    fn drop(&mut self) {
        if let Some(ref mut key) = self.encryption_key {
            key.zeroize();
        }
    }
}

pub struct OutboxEntry {
    pub id: i64,
    pub msg_id: String,
    pub recipient_device_id: String,
    pub envelope: Vec<u8>,
    pub queued_at: u64,
}

impl OutboxQueue {
    /// Open (or create) the outbox database.
    pub fn open(db_path: &Path) -> Result<Self> {
        let db = rusqlite::Connection::open(db_path)?;
        db.execute_batch("PRAGMA journal_mode=WAL;")?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                msg_id TEXT NOT NULL,
                recipient_device_id TEXT NOT NULL,
                envelope BLOB NOT NULL,
                queued_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_outbox_queued ON outbox(queued_at);",
        )?;
        Ok(Self { db, encryption_key: None })
    }

    /// Open an encrypted outbox (convenience constructor).
    pub fn open_encrypted(db_path: &Path, key: [u8; 32]) -> Result<Self> {
        let mut q = Self::open(db_path)?;
        q.encryption_key = Some(key);
        Ok(q)
    }

    /// Encrypt a blob with AES-256-GCM. Returns nonce || ciphertext.
    fn encrypt_blob(&self, data: &[u8]) -> Result<Vec<u8>> {
        match &self.encryption_key {
            Some(key) => {
                let cipher = Aes256Gcm::new_from_slice(key)
                    .map_err(|e| anyhow!("AES key init: {}", e))?;
                let mut nonce_bytes = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);
                let ct = cipher.encrypt(nonce, data)
                    .map_err(|e| anyhow!("outbox encrypt: {}", e))?;
                let mut out = Vec::with_capacity(12 + ct.len());
                out.extend_from_slice(&nonce_bytes);
                out.extend_from_slice(&ct);
                Ok(out)
            }
            None => Ok(data.to_vec()),
        }
    }

    /// Decrypt a blob (nonce || ciphertext) with AES-256-GCM.
    fn decrypt_blob(&self, data: &[u8]) -> Result<Vec<u8>> {
        match &self.encryption_key {
            Some(key) => {
                if data.len() < 12 {
                    return Err(anyhow!("encrypted outbox data too short"));
                }
                let cipher = Aes256Gcm::new_from_slice(key)
                    .map_err(|e| anyhow!("AES key init: {}", e))?;
                let nonce = Nonce::from_slice(&data[..12]);
                cipher.decrypt(nonce, &data[12..])
                    .map_err(|e| anyhow!("outbox decrypt: {}", e))
            }
            None => Ok(data.to_vec()),
        }
    }

    /// Queue an encrypted message for later delivery. Enforces max 1000 messages.
    pub fn queue_message(
        &self,
        recipient_device_id: &str,
        msg_id: &str,
        envelope: &[u8],
    ) -> Result<i64> {
        let count: i64 = self
            .db
            .query_row("SELECT COUNT(*) FROM outbox", [], |row| row.get(0))?;
        if count >= 1000 {
            return Err(anyhow!("outbox full (1000 messages)"));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Encrypt recipient ID and envelope when key is set
        let enc_device_id = if self.encryption_key.is_some() {
            hex::encode(self.encrypt_blob(recipient_device_id.as_bytes())?)
        } else {
            recipient_device_id.to_string()
        };
        let enc_envelope = self.encrypt_blob(envelope)?;

        self.db.execute(
            "INSERT INTO outbox (msg_id, recipient_device_id, envelope, queued_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![msg_id, enc_device_id, enc_envelope, now as i64],
        )?;

        Ok(self.db.last_insert_rowid())
    }

    /// Get all pending messages (oldest first), pruning expired (>7 days).
    pub fn pending_messages(&self) -> Result<Vec<OutboxEntry>> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let seven_days_ago = now.saturating_sub(7 * 24 * 60 * 60);

        // Prune expired entries
        self.db.execute(
            "DELETE FROM outbox WHERE queued_at < ?1",
            [seven_days_ago as i64],
        )?;

        let mut stmt = self.db.prepare(
            "SELECT id, msg_id, recipient_device_id, envelope, queued_at FROM outbox ORDER BY queued_at ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)? as u64,
            ))
        })?;

        let mut entries = Vec::new();
        for row in rows {
            let (id, msg_id, raw_device_id, raw_envelope, queued_at) = row?;

            // Decrypt if encryption key is set (gracefully handle legacy unencrypted data)
            let recipient_device_id = if self.encryption_key.is_some() {
                match hex::decode(&raw_device_id) {
                    Ok(enc_bytes) => match self.decrypt_blob(&enc_bytes) {
                        Ok(plain) => String::from_utf8(plain)
                            .unwrap_or_else(|_| raw_device_id.clone()),
                        Err(_) => raw_device_id, // legacy unencrypted row
                    },
                    Err(_) => raw_device_id, // legacy unencrypted row (plain UUID with hyphens)
                }
            } else {
                raw_device_id
            };
            let envelope = match self.decrypt_blob(&raw_envelope) {
                Ok(e) => e,
                Err(_) => raw_envelope, // legacy unencrypted envelope
            };

            entries.push(OutboxEntry {
                id,
                msg_id,
                recipient_device_id,
                envelope,
                queued_at,
            });
        }
        Ok(entries)
    }

    /// Remove a message after successful send.
    pub fn mark_sent(&self, id: i64) -> Result<()> {
        self.db.execute("DELETE FROM outbox WHERE id = ?1", [id])?;
        Ok(())
    }

    /// Count pending messages.
    pub fn pending_count(&self) -> Result<u64> {
        let count: i64 = self
            .db
            .query_row("SELECT COUNT(*) FROM outbox", [], |row| row.get(0))?;
        Ok(count as u64)
    }
}
