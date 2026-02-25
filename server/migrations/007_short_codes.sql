-- Add short codes to devices for human-friendly buddy discovery
ALTER TABLE devices ADD COLUMN IF NOT EXISTS short_code VARCHAR(9) UNIQUE;
CREATE INDEX IF NOT EXISTS idx_devices_short_code ON devices (short_code);
