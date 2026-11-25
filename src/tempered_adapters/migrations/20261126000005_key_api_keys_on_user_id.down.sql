ALTER TABLE api_keys ADD COLUMN owner_email TEXT;
UPDATE api_keys k SET owner_email = u.email FROM users u WHERE u.id = k.owner;
DELETE FROM api_keys WHERE owner_email IS NULL;
DROP INDEX IF EXISTS api_keys_owner_idx;
ALTER TABLE api_keys DROP COLUMN owner;
ALTER TABLE api_keys RENAME COLUMN owner_email TO owner;
ALTER TABLE api_keys ALTER COLUMN owner SET NOT NULL;
CREATE INDEX api_keys_owner_idx ON api_keys (owner);
