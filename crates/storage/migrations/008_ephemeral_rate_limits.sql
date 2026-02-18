-- +goose Up
-- General-purpose ephemeral rate limiting table. Each row records a single
-- rate-limited action (e.g., "invitation", "membership_append") by an actor.
-- Rows are cleaned up periodically — not stored permanently.
CREATE TABLE rate_limit_actions (
    action     VARCHAR(32) NOT NULL,
    actor_hash CHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_rate_limit_actions_lookup ON rate_limit_actions(action, actor_hash, created_at);

ALTER TABLE invitations DROP COLUMN rate_limit_hash;
DROP INDEX IF EXISTS idx_invitations_rate_limit;

-- +goose Down
ALTER TABLE invitations ADD COLUMN rate_limit_hash CHAR(64);
CREATE INDEX idx_invitations_rate_limit ON invitations(rate_limit_hash, created_at DESC);

DROP INDEX IF EXISTS idx_rate_limit_actions_lookup;
DROP TABLE IF EXISTS rate_limit_actions;
