-- Record ids are unique only within a space: deterministic ids (uuid-v5
-- seeded defaults) are identical across accounts, and federated spaces can
-- legitimately reuse ids minted on their home server. The original global
-- PRIMARY KEY (id) made a second account's push of the same id fail with a
-- records_pkey unique violation — unclassified by the push handler, it
-- surfaced as "internal" and clients retried the wedge forever instead of
-- taking the per-space conflict path.
ALTER TABLE files DROP CONSTRAINT files_record_fk;
ALTER TABLE records DROP CONSTRAINT records_pkey;
ALTER TABLE records ADD PRIMARY KEY (space_id, id);
ALTER TABLE files ADD CONSTRAINT files_record_fk
  FOREIGN KEY (space_id, record_id) REFERENCES records(space_id, id);
