-- AUD-039: record tombstones orphan their encrypted file objects; the
-- physical objects now move through a deletion queue swept by a grace-
-- period background task.
CREATE TABLE pending_file_deletions (
    space_id UUID NOT NULL,
    file_id UUID NOT NULL,
    scheduled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (space_id, file_id)
);

CREATE INDEX idx_pending_file_deletions_scheduled_at ON pending_file_deletions(scheduled_at);
