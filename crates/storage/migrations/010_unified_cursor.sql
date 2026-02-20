-- Unified cursor schema migration.
--
-- Unifies the sequence tracking across records, members, and files into a
-- single monotonic `cursor` per space. This enables unified catch-up queries
-- (UNION ALL ordered by cursor) for WebSocket and federation protocols.

-- spaces: rename sequence → cursor
ALTER TABLE spaces RENAME COLUMN sequence TO cursor;

-- records: rename sequence → cursor, add deleted flag
ALTER TABLE records RENAME COLUMN sequence TO cursor;
ALTER TABLE records ADD COLUMN deleted BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE records SET deleted = TRUE WHERE blob IS NULL;

-- Recreate index with new column name
DROP INDEX IF EXISTS idx_records_sync;
CREATE INDEX idx_records_sync ON records(space_id, cursor, id);

-- members: rename seq → chain_seq, add cursor for unified catch-up
ALTER TABLE members RENAME COLUMN seq TO chain_seq;
ALTER TABLE members ADD COLUMN cursor BIGINT NOT NULL DEFAULT 0;
CREATE INDEX idx_members_cursor ON members(space_id, cursor);

-- files: drop file_seq, add cursor and deleted flag
-- Drop old indexes and constraints first
DROP INDEX IF EXISTS idx_files_space_dek;
ALTER TABLE files DROP CONSTRAINT IF EXISTS files_size_positive;
ALTER TABLE files DROP CONSTRAINT IF EXISTS files_wrapped_dek_length;

ALTER TABLE files DROP COLUMN file_seq;
ALTER TABLE files ADD COLUMN cursor BIGINT NOT NULL DEFAULT 0;
ALTER TABLE files ADD COLUMN deleted BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE files ADD CONSTRAINT files_not_deleted_check
    CHECK (deleted OR (size >= 0 AND wrapped_dek IS NOT NULL AND length(wrapped_dek) = 44));

-- Drop old file indexes, create new ones
DROP INDEX IF EXISTS idx_files_space_id;
DROP INDEX IF EXISTS idx_files_created_at;
CREATE INDEX idx_files_space_cursor ON files(space_id, cursor);
-- idx_files_record_id already exists from migration 005
