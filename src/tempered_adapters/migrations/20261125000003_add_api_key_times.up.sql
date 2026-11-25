-- When each key was made, when it stops working, and when it was last used.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS created_at BIGINT NOT NULL DEFAULT 0;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS expires_at BIGINT;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS last_used_at BIGINT;
