-- TOTP data belongs to the account, not its address: key it on users.id,
-- and let deleting the account delete it.
ALTER TABLE totp_secrets ADD COLUMN user_id UUID;
UPDATE totp_secrets t SET user_id = u.id FROM users u WHERE u.email = t.email;
DELETE FROM totp_secrets WHERE user_id IS NULL;
ALTER TABLE totp_secrets DROP CONSTRAINT totp_secrets_pkey;
ALTER TABLE totp_secrets DROP COLUMN email;
ALTER TABLE totp_secrets ALTER COLUMN user_id SET NOT NULL;
ALTER TABLE totp_secrets ADD PRIMARY KEY (user_id);
ALTER TABLE totp_secrets ADD FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE;

ALTER TABLE totp_recovery_codes ADD COLUMN user_id UUID;
UPDATE totp_recovery_codes t SET user_id = u.id FROM users u WHERE u.email = t.email;
DELETE FROM totp_recovery_codes WHERE user_id IS NULL;
ALTER TABLE totp_recovery_codes DROP CONSTRAINT totp_recovery_codes_pkey;
ALTER TABLE totp_recovery_codes DROP COLUMN email;
ALTER TABLE totp_recovery_codes ALTER COLUMN user_id SET NOT NULL;
ALTER TABLE totp_recovery_codes ADD PRIMARY KEY (user_id, code_hash);
ALTER TABLE totp_recovery_codes ADD FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE;
