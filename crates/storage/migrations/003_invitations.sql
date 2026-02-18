-- +goose Up
CREATE TABLE invitations (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    recipient_hash    CHAR(64) NOT NULL,
    sender_hash       CHAR(64) NOT NULL,
    payload           BYTEA NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_invitations_recipient ON invitations(recipient_hash, created_at DESC);
CREATE INDEX idx_invitations_sender ON invitations(sender_hash, created_at DESC);
CREATE INDEX idx_invitations_expires_at ON invitations(expires_at);

-- +goose Down
DROP INDEX IF EXISTS idx_invitations_expires_at;
DROP INDEX IF EXISTS idx_invitations_sender;
DROP INDEX IF EXISTS idx_invitations_recipient;
DROP TABLE IF EXISTS invitations;
