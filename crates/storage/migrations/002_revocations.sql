CREATE TABLE revocations (
    space_id   UUID NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    ucan_cid   TEXT NOT NULL,
    revoked_by TEXT NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (space_id, ucan_cid)
);
