-- A passkey belongs to the account, not its address: `owner` becomes the
-- account's id, and deleting the account deletes its passkeys.
ALTER TABLE passkey_credentials ADD COLUMN owner_id UUID;
UPDATE passkey_credentials p SET owner_id = u.id FROM users u WHERE u.email = p.owner;
DELETE FROM passkey_credentials WHERE owner_id IS NULL;
DROP INDEX IF EXISTS passkey_credentials_owner_idx;
ALTER TABLE passkey_credentials DROP COLUMN owner;
ALTER TABLE passkey_credentials RENAME COLUMN owner_id TO owner;
ALTER TABLE passkey_credentials ALTER COLUMN owner SET NOT NULL;
ALTER TABLE passkey_credentials ADD FOREIGN KEY (owner) REFERENCES users (id) ON DELETE CASCADE;
CREATE INDEX passkey_credentials_owner_idx ON passkey_credentials (owner);
