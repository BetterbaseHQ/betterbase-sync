-- Wrapped epoch-key shares for fresh-key rotation (AUD-024 / D-005).
--
-- When a shared space rotates its epoch key with a FRESH random secret, the
-- rotating admin stores one wrapped copy of that key per remaining member
-- (admins included). Members pull their own share on the next sync; the
-- server never sees plaintext key material (same trust model as
-- invitations). Distribution happens BEFORE any DEK rewrap so a crashed
-- originator can never leave ciphertext under a lost key.

CREATE TABLE epoch_keys (
    space_id    UUID NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    epoch       INT  NOT NULL,
    member_did  TEXT NOT NULL,
    wrapped_key BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (space_id, epoch, member_did)
);

CREATE INDEX idx_epoch_keys_member ON epoch_keys(space_id, member_did);
