-- TOTP secrets: at most one pending (being enrolled) and one active per user.
CREATE TABLE IF NOT EXISTS totp_secrets (
    email TEXT PRIMARY KEY,
    pending BYTEA,
    active BYTEA,
    -- The last time step a code was accepted for; codes for it or earlier
    -- are refused (no replays).
    last_step BIGINT
);

-- SHA-256 hashes of unused recovery codes.
CREATE TABLE IF NOT EXISTS totp_recovery_codes (
    email TEXT NOT NULL,
    code_hash BYTEA NOT NULL,
    PRIMARY KEY (email, code_hash)
);
