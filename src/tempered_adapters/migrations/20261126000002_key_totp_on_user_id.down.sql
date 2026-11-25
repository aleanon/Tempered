ALTER TABLE totp_recovery_codes ADD COLUMN email TEXT;
UPDATE totp_recovery_codes t SET email = u.email FROM users u WHERE u.id = t.user_id;
ALTER TABLE totp_recovery_codes DROP CONSTRAINT totp_recovery_codes_pkey;
ALTER TABLE totp_recovery_codes DROP COLUMN user_id;
ALTER TABLE totp_recovery_codes ALTER COLUMN email SET NOT NULL;
ALTER TABLE totp_recovery_codes ADD PRIMARY KEY (email, code_hash);

ALTER TABLE totp_secrets ADD COLUMN email TEXT;
UPDATE totp_secrets t SET email = u.email FROM users u WHERE u.id = t.user_id;
ALTER TABLE totp_secrets DROP CONSTRAINT totp_secrets_pkey;
ALTER TABLE totp_secrets DROP COLUMN user_id;
ALTER TABLE totp_secrets ALTER COLUMN email SET NOT NULL;
ALTER TABLE totp_secrets ADD PRIMARY KEY (email);
