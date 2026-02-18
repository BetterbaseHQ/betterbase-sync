-- +goose Up
-- Phase 1: Remove unnecessary metadata that is stored but never queried.

-- revocations: revoked_by (plaintext DID) and revoked_at are never read —
-- only IsRevoked(spaceID, ucanCID) checks existence.
ALTER TABLE revocations DROP COLUMN revoked_by;
ALTER TABLE revocations DROP COLUMN revoked_at;

-- files: created_at and its index are never queried.
DROP INDEX IF EXISTS idx_files_created_at;
ALTER TABLE files DROP COLUMN created_at;

-- members: created_at is never read back.
ALTER TABLE members DROP COLUMN created_at;

-- +goose Down
ALTER TABLE members ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE files ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
CREATE INDEX idx_files_created_at ON files(created_at);
ALTER TABLE revocations ADD COLUMN revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE revocations ADD COLUMN revoked_by TEXT NOT NULL DEFAULT '';
