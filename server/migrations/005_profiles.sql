-- Add profile fields to devices table
ALTER TABLE devices ADD COLUMN IF NOT EXISTS display_name VARCHAR(64);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS bio VARCHAR(256);
