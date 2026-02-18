-- +goose Up
ALTER TABLE files ADD COLUMN record_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';
ALTER TABLE files ALTER COLUMN record_id DROP DEFAULT;
ALTER TABLE files ADD CONSTRAINT files_record_fk FOREIGN KEY (record_id) REFERENCES records(id);
CREATE INDEX idx_files_record_id ON files(record_id);

-- +goose Down
DROP INDEX IF EXISTS idx_files_record_id;
ALTER TABLE files DROP CONSTRAINT IF EXISTS files_record_fk;
ALTER TABLE files DROP COLUMN IF EXISTS record_id;
