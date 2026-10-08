-- File tombstones (direct DELETE route) shed their wrapped DEK: the
-- metadata row stays to stream `deleted` through cursor-based pull, but a
-- tombstone carries no key material and no size expectations. The existing
-- `files_not_deleted_check` (migration 010) keeps live rows honest —
-- deleted=FALSE requires a 44-byte wrapper.

ALTER TABLE files ALTER COLUMN wrapped_dek DROP NOT NULL;
