CREATE TABLE federation_signing_keys (
    kid         TEXT PRIMARY KEY,
    private_key BYTEA NOT NULL,
    public_key  BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE spaces ADD COLUMN home_server TEXT;
