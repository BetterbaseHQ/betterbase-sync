-- +goose Up
-- Track in-progress epoch rewraps. When set, epoch was advanced but DEKs
-- haven't been fully re-wrapped yet. Any admin can discover this on pull
-- and complete the work. Cannot advance epoch while rewrap_epoch is set.
ALTER TABLE spaces ADD COLUMN rewrap_epoch INTEGER;

-- +goose Down
ALTER TABLE spaces DROP COLUMN rewrap_epoch;
