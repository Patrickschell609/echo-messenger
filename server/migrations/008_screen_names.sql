-- Screen names: user-chosen unique identifiers (like AIM screen names)
ALTER TABLE devices ADD COLUMN IF NOT EXISTS screen_name VARCHAR(20);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS screen_name_lower VARCHAR(20);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS screen_name_changed_at TIMESTAMPTZ;

-- Case-insensitive uniqueness (NULL values excluded so existing devices are fine)
CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_screen_name_lower
    ON devices (screen_name_lower) WHERE screen_name_lower IS NOT NULL;
