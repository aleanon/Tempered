-- An API key's owner is an id: an account's, which stays when its address
-- changes, or one the app gives a service. Not a foreign key, since a
-- service need not be an account; deleting an account deletes its keys
-- explicitly. Keys whose owner is not an account's address cannot be
-- converted and are dropped (issue them again with an id).
ALTER TABLE api_keys ADD COLUMN owner_id UUID;
UPDATE api_keys k SET owner_id = u.id FROM users u WHERE u.email = k.owner;
DELETE FROM api_keys WHERE owner_id IS NULL;
DROP INDEX IF EXISTS api_keys_owner_idx;
ALTER TABLE api_keys DROP COLUMN owner;
ALTER TABLE api_keys RENAME COLUMN owner_id TO owner;
ALTER TABLE api_keys ALTER COLUMN owner SET NOT NULL;
CREATE INDEX api_keys_owner_idx ON api_keys (owner);
