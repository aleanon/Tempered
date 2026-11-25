ALTER TABLE passkey_credentials ADD COLUMN owner_email TEXT;
UPDATE passkey_credentials p SET owner_email = u.email FROM users u WHERE u.id = p.owner;
DROP INDEX IF EXISTS passkey_credentials_owner_idx;
ALTER TABLE passkey_credentials DROP COLUMN owner;
ALTER TABLE passkey_credentials RENAME COLUMN owner_email TO owner;
ALTER TABLE passkey_credentials ALTER COLUMN owner SET NOT NULL;
CREATE INDEX passkey_credentials_owner_idx ON passkey_credentials (owner);
