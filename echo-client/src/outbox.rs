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

use anyhow::{anyhow, Result};

pub struct OutboxQueue {
    db: rusqlite::Connection,
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
        Ok(Self { db })
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

        self.db.execute(
            "INSERT INTO outbox (msg_id, recipient_device_id, envelope, queued_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![msg_id, recipient_device_id, envelope, now as i64],
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
            Ok(OutboxEntry {
                id: row.get(0)?,
                msg_id: row.get(1)?,
                recipient_device_id: row.get(2)?,
                envelope: row.get(3)?,
                queued_at: row.get::<_, i64>(4)? as u64,
            })
        })?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
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
