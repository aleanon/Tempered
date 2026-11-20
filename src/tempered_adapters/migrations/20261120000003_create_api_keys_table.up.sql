-- API keys, stored as the SHA-256 of their secret half; looked up by the
-- non-secret prefix.
CREATE TABLE IF NOT EXISTS api_keys(
   id TEXT NOT NULL PRIMARY KEY,
   prefix TEXT NOT NULL UNIQUE,
   secret_hash TEXT NOT NULL,
   owner TEXT NOT NULL,
   scopes TEXT[] NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS api_keys_owner_idx ON api_keys (owner);
