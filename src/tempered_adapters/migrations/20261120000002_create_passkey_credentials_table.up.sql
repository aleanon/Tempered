-- Enrolled WebAuthn credentials. The id is globally unique: a credential is
-- never handed to another owner.
CREATE TABLE IF NOT EXISTS passkey_credentials(
   credential_id TEXT NOT NULL PRIMARY KEY,
   owner TEXT NOT NULL,
   credential_data BYTEA NOT NULL,
   sign_count BIGINT NOT NULL CHECK (sign_count >= 0 AND sign_count <= 4294967295)
);
CREATE INDEX IF NOT EXISTS passkey_credentials_owner_idx ON passkey_credentials (owner);
