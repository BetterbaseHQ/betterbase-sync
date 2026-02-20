-- Phase 2: Rewrite invitations to use client-derived mailbox_id instead of
-- server-computed recipient/sender hashes. Greenfield — no backwards compat needed.
DROP TABLE invitations;

CREATE TABLE invitations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mailbox_id      CHAR(64) NOT NULL,
    rate_limit_hash CHAR(64) NOT NULL,
    payload         BYTEA NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_invitations_mailbox ON invitations(mailbox_id, created_at DESC);
CREATE INDEX idx_invitations_rate_limit ON invitations(rate_limit_hash, created_at DESC);
CREATE INDEX idx_invitations_expires_at ON invitations(expires_at);
