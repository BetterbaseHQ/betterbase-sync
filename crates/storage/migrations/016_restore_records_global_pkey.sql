-- Restore records(id) as the globally unique primary key (reverts 015).
--
-- Record ids are random UUIDs unique across the platform by construction;
-- moveToSpace re-identifies records on space changes precisely to preserve
-- that guarantee. 015 relaxed uniqueness to (space_id, id) to accommodate
-- deterministic default-record ids that collided across accounts — the wrong
-- fix for a client-side problem. See examples docs/scaffold-data-design.md.
--
-- Preflight: fail loudly (not with a raw constraint error) if any id exists
-- in more than one space. Clean stacks (prod never shipped 015; fresh e2e
-- volumes) have no duplicates. A dev stack that ran v5 examples must be
-- reset first: `just dev-down -v` plus browser origin storage reset.
DO $$
DECLARE
  offenders INTEGER;
BEGIN
  SELECT COUNT(*) INTO offenders FROM (
    SELECT id FROM records GROUP BY id HAVING COUNT(*) > 1
  ) dupes;
  IF offenders > 0 THEN
    RAISE EXCEPTION 'records: % id(s) exist in multiple spaces; cannot restore global primary key. This database ran deterministic-id example builds. Reset the stack (dev: just dev-down -v; e2e: just e2e-clean) before applying this migration.', offenders;
  END IF;
END $$;

ALTER TABLE files DROP CONSTRAINT files_record_fk;
ALTER TABLE records DROP CONSTRAINT records_pkey;
ALTER TABLE records ADD PRIMARY KEY (id);
-- The global PK implies (space_id, id) uniqueness; the explicit UNIQUE
-- constraint gives files_record_fk a same-space target, so a files row can
-- never reference a record in a different space (which would dodge the
-- tombstone cascade and leak its blob from storage accounting).
ALTER TABLE records ADD CONSTRAINT records_space_id_unique UNIQUE (space_id, id);
ALTER TABLE files ADD CONSTRAINT files_record_fk
  FOREIGN KEY (space_id, record_id) REFERENCES records(space_id, id);
