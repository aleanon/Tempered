-- A provider link belongs to the account, not its address: key it on
-- users.id, and let deleting the account delete its links.
ALTER TABLE oauth_identities ADD COLUMN user_id UUID;
UPDATE oauth_identities o SET user_id = u.id FROM users u WHERE u.email = o.email;
DELETE FROM oauth_identities WHERE user_id IS NULL;
DROP INDEX IF EXISTS oauth_identities_email_idx;
ALTER TABLE oauth_identities DROP COLUMN email;
ALTER TABLE oauth_identities ALTER COLUMN user_id SET NOT NULL;
ALTER TABLE oauth_identities ADD FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE;
CREATE INDEX oauth_identities_user_id_idx ON oauth_identities (user_id);
