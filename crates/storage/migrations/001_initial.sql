-- +goose Up

-- A space is a sync namespace. Personal spaces have root_public_key = NULL
-- and are authenticated via JWT only. Shared spaces have a root_public_key
-- and require JWT + UCAN for authorization.
CREATE TABLE spaces (
    id                  UUID PRIMARY KEY,
    client_id           TEXT NOT NULL,
    root_public_key     BYTEA,                          -- NULL = personal, SET = shared
    key_generation      INTEGER NOT NULL DEFAULT 1,
    min_key_generation  INTEGER NOT NULL DEFAULT 1,
    metadata_version    INTEGER NOT NULL DEFAULT 0,
    sequence            BIGINT NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Records table
CREATE TABLE records (
    id UUID PRIMARY KEY,
    space_id UUID NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    blob BYTEA,
    sequence BIGINT NOT NULL
);

CREATE INDEX idx_records_sync ON records(space_id, sequence, id);

-- Files table tracks file metadata for storage accounting and cleanup.
-- Actual file content is stored externally (filesystem or S3).
-- Files are identified by client-generated UUIDs (no content-addressing).
CREATE TABLE files (
    space_id UUID NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    id UUID NOT NULL,
    size BIGINT NOT NULL,
    wrapped_dek BYTEA NOT NULL,
    file_seq BIGSERIAL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (space_id, id),
    CONSTRAINT files_size_positive CHECK (size >= 0),
    CONSTRAINT files_wrapped_dek_length CHECK (length(wrapped_dek) = 44)
);

CREATE INDEX idx_files_space_id ON files(space_id);
CREATE INDEX idx_files_created_at ON files(created_at);
CREATE INDEX idx_files_space_dek ON files(space_id, file_seq);

-- Members log table stores opaque encrypted membership entries as a hash chain.
-- The server validates structure (hash chain, CAS on metadata_version) but never
-- interprets entry contents.
CREATE TABLE members (
    space_id    UUID NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    seq         INTEGER NOT NULL,
    prev_hash   BYTEA,
    entry_hash  BYTEA NOT NULL,
    payload     BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (space_id, seq)
);

-- +goose StatementBegin
CREATE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Triggers for updated_at
CREATE TRIGGER spaces_updated_at BEFORE UPDATE ON spaces
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- +goose Down
DROP TRIGGER IF EXISTS spaces_updated_at ON spaces;
DROP FUNCTION IF EXISTS update_updated_at_column();
DROP TABLE IF EXISTS members;
DROP INDEX IF EXISTS idx_files_space_dek;
DROP INDEX IF EXISTS idx_files_created_at;
DROP INDEX IF EXISTS idx_files_space_id;
DROP TABLE IF EXISTS files;
DROP TABLE IF EXISTS records;
DROP TABLE IF EXISTS spaces;
