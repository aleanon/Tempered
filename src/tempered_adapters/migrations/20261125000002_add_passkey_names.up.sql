-- What the user calls each passkey ("work laptop").
ALTER TABLE passkey_credentials ADD COLUMN IF NOT EXISTS name TEXT;
