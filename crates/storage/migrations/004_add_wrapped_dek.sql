-- +goose Up
ALTER TABLE records ADD COLUMN wrapped_dek BYTEA;

-- +goose Down
ALTER TABLE records DROP COLUMN IF EXISTS wrapped_dek;
