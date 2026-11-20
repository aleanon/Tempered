-- Provider identities linked to local accounts. A (provider, subject) pair
-- maps to exactly one account and is never moved to another.
CREATE TABLE IF NOT EXISTS oauth_identities(
   provider TEXT NOT NULL,
   subject TEXT NOT NULL,
   email TEXT NOT NULL,
   PRIMARY KEY (provider, subject)
);
CREATE INDEX IF NOT EXISTS oauth_identities_email_idx ON oauth_identities (email);
