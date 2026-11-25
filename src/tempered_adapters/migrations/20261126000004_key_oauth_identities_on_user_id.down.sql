ALTER TABLE oauth_identities ADD COLUMN email TEXT;
UPDATE oauth_identities o SET email = u.email FROM users u WHERE u.id = o.user_id;
DROP INDEX IF EXISTS oauth_identities_user_id_idx;
ALTER TABLE oauth_identities DROP COLUMN user_id;
ALTER TABLE oauth_identities ALTER COLUMN email SET NOT NULL;
CREATE INDEX oauth_identities_email_idx ON oauth_identities (email);
