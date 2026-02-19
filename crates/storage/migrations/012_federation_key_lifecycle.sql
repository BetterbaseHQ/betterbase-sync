-- +goose Up
ALTER TABLE federation_signing_keys
    ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN deactivated_at TIMESTAMPTZ;

WITH first_key AS (
    SELECT kid
    FROM federation_signing_keys
    ORDER BY created_at ASC, kid ASC
    LIMIT 1
)
UPDATE federation_signing_keys
SET is_primary = TRUE
WHERE kid IN (SELECT kid FROM first_key);

CREATE UNIQUE INDEX federation_signing_keys_single_primary_idx
    ON federation_signing_keys ((is_primary))
    WHERE is_primary = TRUE;

-- +goose Down
DROP INDEX IF EXISTS federation_signing_keys_single_primary_idx;

ALTER TABLE federation_signing_keys
    DROP COLUMN IF EXISTS deactivated_at,
    DROP COLUMN IF EXISTS is_primary,
    DROP COLUMN IF EXISTS is_active;
