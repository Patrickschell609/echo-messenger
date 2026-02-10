-- Group messaging tables

ALTER TABLE groups ADD COLUMN IF NOT EXISTS name VARCHAR(128);
ALTER TABLE groups ADD COLUMN IF NOT EXISTS creator_device_id UUID REFERENCES devices(id);

CREATE TABLE IF NOT EXISTS group_messages (
    id BIGSERIAL PRIMARY KEY,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    sender_device_id UUID NOT NULL REFERENCES devices(id),
    payload BYTEA NOT NULL,
    queued_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_group_messages_group ON group_messages(group_id, id);

CREATE TABLE IF NOT EXISTS group_read_cursors (
    group_id UUID NOT NULL,
    device_id UUID NOT NULL,
    last_read_id BIGINT DEFAULT 0,
    PRIMARY KEY (group_id, device_id)
);
