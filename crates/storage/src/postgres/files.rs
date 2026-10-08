use async_trait::async_trait;
use std::time::SystemTime;
use uuid::Uuid;

use super::PostgresStorage;
use crate::{FileDekRecord, FileMetadata, FileQuota, FileStorage, StorageError};

use sqlx::{Postgres, Transaction};

pub(super) const WRAPPED_DEK_LENGTH: usize = 44;

#[async_trait]
impl FileStorage for PostgresStorage {
    async fn lock_file(
        &self,
        space_id: Uuid,
        file_id: Uuid,
    ) -> Result<crate::FileOperationLock, StorageError> {
        let mut tx = self
            .file_lock_pool
            .begin()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("betterbase-sync:file:{space_id}:{file_id}"))
            .execute(tx.as_mut())
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        // Transaction rollback on Drop also releases the lock on cancellation.
        Ok(Box::new(tx))
    }

    async fn record_file(
        &self,
        space_id: Uuid,
        file_id: Uuid,
        record_id: Uuid,
        size: i64,
        wrapped_dek: &[u8],
    ) -> Result<Option<i64>, StorageError> {
        if wrapped_dek.len() != WRAPPED_DEK_LENGTH {
            return Err(StorageError::InvalidWrappedDek);
        }
        if size < 0 {
            return Err(StorageError::InvalidFileSize);
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

        let cursor = super::get_space_cursor_for_update(&mut tx, space_id).await?;
        let parent_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM records WHERE space_id = $1 AND id = $2 AND deleted = FALSE)",
        ).bind(space_id).bind(record_id).fetch_one(tx.as_mut()).await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        if !parent_exists {
            return Err(StorageError::RecordNotFound);
        }
        let new_cursor = cursor + 1;

        // AUD-029 (files): enforce the space's minimum key generation on file
        // DEKs too — a stale-but-authorized device must not land wrappers the
        // post-rotation key hierarchy cannot decrypt. The space row is locked
        // by the cursor SELECT above, so the check races no rotation.
        {
            let row = sqlx::query_as::<_, SpaceGenRow>(
                "SELECT root_public_key, min_epoch FROM spaces WHERE id = $1",
            )
            .bind(space_id)
            .fetch_one(tx.as_mut())
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
            if row.root_public_key.is_some() {
                if let Some(epoch) = super::parse_dek_epoch(wrapped_dek) {
                    if epoch < row.min_epoch {
                        return Err(StorageError::EpochStale);
                    }
                }
            }
        }

        // A live row means idempotent replay (no state change); a soft-deleted
        // row is resurrected by this upload (the sweep's re-upload guard:
        // committing metadata makes the object live again). The per-file
        // advisory lock serializes this against tombstones and other uploads.
        let existing: Option<bool> =
            sqlx::query_scalar("SELECT deleted FROM files WHERE space_id = $1 AND id = $2")
                .bind(space_id)
                .bind(file_id)
                .fetch_optional(tx.as_mut())
                .await
                .map_err(|error| StorageError::Database(error.to_string()))?;

        let created = match existing {
            // Live row — idempotent replay of a fully-recorded upload.
            Some(false) => false,
            // New row (or resurrection): enforce the per-space quota against
            // live files before allocating any storage for it.
            Some(true) | None => {
                enforce_file_quota(&mut tx, space_id, &self.file_quota, size).await?;
                sqlx::query(
                    r#"
                    INSERT INTO files (space_id, id, record_id, size, wrapped_dek, cursor)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    ON CONFLICT (space_id, id) DO UPDATE SET
                        deleted = FALSE,
                        record_id = EXCLUDED.record_id,
                        size = EXCLUDED.size,
                        wrapped_dek = EXCLUDED.wrapped_dek,
                        cursor = EXCLUDED.cursor
                    "#,
                )
                .bind(space_id)
                .bind(file_id)
                .bind(record_id)
                .bind(size)
                .bind(wrapped_dek)
                .bind(new_cursor)
                .execute(tx.as_mut())
                .await
                .map_err(|error| StorageError::Database(error.to_string()))?;
                true
            }
        };

        if created {
            sqlx::query("UPDATE spaces SET cursor = $2 WHERE id = $1")
                .bind(space_id)
                .bind(new_cursor)
                .execute(tx.as_mut())
                .await
                .map_err(|error| StorageError::Database(error.to_string()))?;
        }
        // Clear the upload's cleanup intent atomically with metadata. A later
        // tombstone holds the same space lock and will create a fresh intent.
        sqlx::query("DELETE FROM pending_file_deletions WHERE space_id = $1 AND file_id = $2")
            .bind(space_id)
            .bind(file_id)
            .execute(tx.as_mut())
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        tx.commit()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(created.then_some(new_cursor))
    }

    async fn tombstone_file(
        &self,
        space_id: Uuid,
        file_id: Uuid,
    ) -> Result<Option<i64>, StorageError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

        let cursor = super::get_space_cursor_for_update(&mut tx, space_id).await?;
        let new_cursor = cursor + 1;

        // Soft-delete: the row stays (wrapped DEK dropped — the CHECK allows
        // NULL only for deleted rows) so the tombstone streams through
        // cursor-based pull; the object is queued for grace-period removal
        // in the same transaction (AUD-039 crash-safety shape).
        let tombstoned: Option<Uuid> = sqlx::query_scalar(
            r#"
            UPDATE files
            SET deleted = TRUE, wrapped_dek = NULL, cursor = $3
            WHERE space_id = $1 AND id = $2 AND deleted = FALSE
            RETURNING id
            "#,
        )
        .bind(space_id)
        .bind(file_id)
        .bind(new_cursor)
        .fetch_optional(tx.as_mut())
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;

        if tombstoned.is_none() {
            tx.rollback()
                .await
                .map_err(|error| StorageError::Database(error.to_string()))?;
            return Ok(None);
        }

        sqlx::query("UPDATE spaces SET cursor = $2 WHERE id = $1")
            .bind(space_id)
            .bind(new_cursor)
            .execute(tx.as_mut())
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

        // Refresh any prior intent so the grace period starts at this
        // tombstone (mirrors the record-cascade path).
        sqlx::query(
            "INSERT INTO pending_file_deletions (space_id, file_id) VALUES ($1, $2)
             ON CONFLICT (space_id, file_id) DO UPDATE SET scheduled_at = EXCLUDED.scheduled_at",
        )
        .bind(space_id)
        .bind(file_id)
        .execute(tx.as_mut())
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;

        tx.commit()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(Some(new_cursor))
    }

    async fn get_file_metadata(
        &self,
        space_id: Uuid,
        file_id: Uuid,
    ) -> Result<FileMetadata, StorageError> {
        let row = sqlx::query_as::<_, FileMetadataRow>(
            r#"
            SELECT id, record_id, size, wrapped_dek, cursor
            FROM files
            WHERE space_id = $1 AND id = $2 AND deleted = FALSE
            "#,
        )
        .bind(space_id)
        .bind(file_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| match error {
            sqlx::Error::RowNotFound => StorageError::FileNotFound,
            _ => StorageError::Database(error.to_string()),
        })?;

        Ok(FileMetadata {
            id: row.id,
            record_id: row.record_id,
            size: row.size,
            wrapped_dek: row.wrapped_dek,
            cursor: row.cursor,
        })
    }

    async fn file_exists(&self, space_id: Uuid, file_id: Uuid) -> Result<bool, StorageError> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM files WHERE space_id = $1 AND id = $2 AND deleted = FALSE)",
        )
        .bind(space_id)
        .bind(file_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(exists)
    }

    async fn get_file_deks(
        &self,
        space_id: Uuid,
        since: i64,
    ) -> Result<Vec<FileDekRecord>, StorageError> {
        let rows = sqlx::query_as::<_, FileDekRow>(
            r#"
            SELECT id, wrapped_dek, cursor
            FROM files
            WHERE space_id = $1
              AND cursor > $2
              AND deleted = FALSE
            ORDER BY cursor ASC, id ASC
            "#,
        )
        .bind(space_id)
        .bind(since)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| FileDekRecord {
                id: row.id,
                wrapped_dek: row.wrapped_dek,
                cursor: row.cursor,
                observed_wrapped_dek: None,
            })
            .collect())
    }

    async fn rewrap_file_deks(
        &self,
        space_id: Uuid,
        deks: &[FileDekRecord],
    ) -> Result<(), StorageError> {
        if deks.is_empty() {
            return Ok(());
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

        let epoch: i32 = sqlx::query_scalar("SELECT epoch FROM spaces WHERE id = $1 FOR UPDATE")
            .bind(space_id)
            .fetch_one(tx.as_mut())
            .await
            .map_err(|error| match error {
                sqlx::Error::RowNotFound => StorageError::SpaceNotFound,
                _ => StorageError::Database(error.to_string()),
            })?;

        for dek in deks {
            let dek_epoch =
                super::parse_dek_epoch(&dek.wrapped_dek).ok_or(StorageError::DekEpochMismatch)?;
            if dek_epoch != epoch {
                return Err(StorageError::DekEpochMismatch);
            }
        }

        for dek in deks {
            // Compare-and-set on the observed wrapper (AUD-026), matching the
            // record-DEK rewrap path.
            let result = sqlx::query(
                "UPDATE files SET wrapped_dek = $1 \
                 WHERE id = $2 AND space_id = $3 AND deleted = FALSE \
                 AND ($4::bytea IS NULL OR wrapped_dek = $4)",
            )
            .bind(&dek.wrapped_dek)
            .bind(dek.id)
            .bind(space_id)
            .bind(&dek.observed_wrapped_dek)
            .execute(tx.as_mut())
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

            if result.rows_affected() != 1 {
                return Err(match dek.observed_wrapped_dek {
                    Some(_) => StorageError::DekConflict,
                    None => StorageError::FileDekNotFound,
                });
            }
        }

        tx.commit()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(())
    }

    async fn delete_files_for_records(
        &self,
        space_id: Uuid,
        record_ids: &[Uuid],
    ) -> Result<Vec<Uuid>, StorageError> {
        if record_ids.is_empty() {
            return Ok(Vec::new());
        }

        sqlx::query_scalar::<_, Uuid>(
            "DELETE FROM files WHERE space_id = $1 AND record_id = ANY($2) RETURNING id",
        )
        .bind(space_id)
        .bind(record_ids)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))
    }

    async fn schedule_file_deletions(
        &self,
        space_id: Uuid,
        file_ids: &[Uuid],
    ) -> Result<(), StorageError> {
        for file_id in file_ids {
            sqlx::query(
                "INSERT INTO pending_file_deletions (space_id, file_id) VALUES ($1, $2)
                 ON CONFLICT (space_id, file_id) DO NOTHING",
            )
            .bind(space_id)
            .bind(file_id)
            .execute(&self.pool)
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        }
        Ok(())
    }

    async fn pending_file_deletions(
        &self,
        cutoff: SystemTime,
        limit: usize,
    ) -> Result<Vec<crate::PendingFileDeletion>, StorageError> {
        let cutoff_us = cutoff
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_micros() as i64)
            .unwrap_or(0);
        let rows = sqlx::query_as::<_, PendingDeletionRow>(
            "SELECT space_id, file_id FROM pending_file_deletions
             WHERE (EXTRACT(EPOCH FROM scheduled_at) * 1000000)::BIGINT <= $1
             ORDER BY scheduled_at LIMIT $2",
        )
        .bind(cutoff_us)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|row| crate::PendingFileDeletion {
                space_id: row.space_id,
                file_id: row.file_id,
            })
            .collect())
    }

    async fn file_deletion_due(
        &self,
        space_id: Uuid,
        file_id: Uuid,
        cutoff: SystemTime,
    ) -> Result<bool, StorageError> {
        let cutoff_us = super::system_time_to_unix_micros(cutoff)?;
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pending_file_deletions WHERE space_id = $1 AND file_id = $2 AND (EXTRACT(EPOCH FROM scheduled_at) * 1000000)::BIGINT <= $3)")
            .bind(space_id).bind(file_id).bind(cutoff_us).fetch_one(&self.pool).await
            .map_err(|error| StorageError::Database(error.to_string()))
    }

    async fn clear_file_deletion_if_live(
        &self,
        space_id: Uuid,
        file_id: Uuid,
    ) -> Result<(), StorageError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        match super::get_space_cursor_for_update(&mut tx, space_id).await {
            Ok(_) => {}
            Err(StorageError::SpaceNotFound) => return Ok(()),
            Err(error) => return Err(error),
        }
        sqlx::query("DELETE FROM pending_file_deletions WHERE space_id = $1 AND file_id = $2 AND EXISTS(SELECT 1 FROM files WHERE space_id = $1 AND id = $2 AND deleted = FALSE)")
            .bind(space_id).bind(file_id).execute(tx.as_mut()).await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        tx.commit()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))
    }

    async fn complete_file_deletion(
        &self,
        space_id: Uuid,
        file_id: Uuid,
    ) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM pending_file_deletions WHERE space_id = $1 AND file_id = $2")
            .bind(space_id)
            .bind(file_id)
            .execute(&self.pool)
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(())
    }
}

/// Reject a new live file when it would push the space past its quota.
/// Runs inside the caller's transaction (the space row is already locked,
/// so concurrent commits serialize behind it and cannot overshoot).
///
/// Counts live files PLUS tombstoned files whose objects are still in the
/// deletion queue: their bytes occupy storage until the grace-period sweep
/// completes, so a create→delete churn loop cannot exceed the physical
/// bound by cycling through the grace window.
async fn enforce_file_quota(
    tx: &mut Transaction<'_, Postgres>,
    space_id: Uuid,
    quota: &FileQuota,
    incoming_size: i64,
) -> Result<(), StorageError> {
    if quota.max_files.is_none() && quota.max_bytes.is_none() {
        return Ok(());
    }
    let (live_count, live_bytes): (i64, i64) = sqlx::query_as(
        r#"
        SELECT COUNT(*)::BIGINT, COALESCE(SUM(size), 0)::BIGINT
        FROM files
        WHERE space_id = $1
          AND (deleted = FALSE
               OR EXISTS (SELECT 1 FROM pending_file_deletions p
                          WHERE p.space_id = files.space_id
                            AND p.file_id = files.id))
        "#,
    )
    .bind(space_id)
    .fetch_one(tx.as_mut())
    .await
    .map_err(|error| StorageError::Database(error.to_string()))?;

    if let Some(max_files) = quota.max_files {
        if live_count >= i64::from(max_files) {
            return Err(StorageError::QuotaExceeded);
        }
    }
    if let Some(max_bytes) = quota.max_bytes {
        if live_bytes.saturating_add(incoming_size) > max_bytes {
            return Err(StorageError::QuotaExceeded);
        }
    }
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
struct PendingDeletionRow {
    space_id: Uuid,
    file_id: Uuid,
}

#[derive(Debug, sqlx::FromRow)]
struct SpaceGenRow {
    root_public_key: Option<Vec<u8>>,
    min_epoch: i32,
}

#[derive(Debug, sqlx::FromRow)]
struct FileMetadataRow {
    id: Uuid,
    record_id: Uuid,
    size: i64,
    wrapped_dek: Vec<u8>,
    cursor: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct FileDekRow {
    id: Uuid,
    wrapped_dek: Vec<u8>,
    cursor: i64,
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::super::test_support::*;
    use crate::{FileDekRecord, FileQuota, FileStorage, SpaceStorage, StorageError};

    #[tokio::test]
    async fn file_quota_rejects_new_commits_past_limits() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let storage = storage.with_file_quota(FileQuota {
            max_files: Some(2),
            max_bytes: Some(150),
        });
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;
        let record_id = create_record(&storage, space_id).await;

        storage
            .record_file(
                space_id,
                uuid::Uuid::new_v4(),
                record_id,
                100,
                &wrapped_dek(1),
            )
            .await
            .expect("first file within quota");
        // Second file fits the byte budget exactly (100 + 50 = 150).
        storage
            .record_file(
                space_id,
                uuid::Uuid::new_v4(),
                record_id,
                50,
                &wrapped_dek(2),
            )
            .await
            .expect("second file exactly at byte quota");
        // Third file trips the count limit even though bytes are free-ish.
        assert_eq!(
            storage
                .record_file(
                    space_id,
                    uuid::Uuid::new_v4(),
                    record_id,
                    1,
                    &wrapped_dek(3)
                )
                .await
                .unwrap_err(),
            StorageError::QuotaExceeded
        );
    }

    #[tokio::test]
    async fn tombstone_file_hides_queues_and_frees_quota() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let storage = storage.with_file_quota(FileQuota {
            max_files: Some(1),
            max_bytes: None,
        });
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;
        let record_id = create_record(&storage, space_id).await;
        let file_id = uuid::Uuid::new_v4();

        storage
            .record_file(space_id, file_id, record_id, 10, &wrapped_dek(7))
            .await
            .expect("record file");

        // Tombstone: hidden from reads, queued for GC, idempotent.
        let cursor = storage
            .tombstone_file(space_id, file_id)
            .await
            .expect("tombstone")
            .expect("cursor");
        assert!(cursor > 0);
        assert_eq!(
            storage
                .get_file_metadata(space_id, file_id)
                .await
                .unwrap_err(),
            StorageError::FileNotFound
        );
        assert!(!storage
            .file_exists(space_id, file_id)
            .await
            .expect("exists"));
        assert_eq!(
            storage
                .tombstone_file(space_id, file_id)
                .await
                .expect("idempotent tombstone"),
            None
        );
        let pending = storage
            .pending_file_deletions(
                std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
                10,
            )
            .await
            .expect("pending");
        assert!(pending
            .iter()
            .any(|item| item.space_id == space_id && item.file_id == file_id));

        // Deleted files do not count against the quota: resurrecting the
        // tombstoned id (live count 0 → 1) fits under max_files = 1.
        let resurrect_cursor = storage
            .record_file(space_id, file_id, record_id, 12, &wrapped_dek(9))
            .await
            .expect("resurrect")
            .expect("resurrect cursor");
        assert!(resurrect_cursor > cursor);
        assert!(storage
            .file_exists(space_id, file_id)
            .await
            .expect("exists"));
        let metadata = storage
            .get_file_metadata(space_id, file_id)
            .await
            .expect("live again");
        assert_eq!(metadata.size, 12);
        let pending = storage
            .pending_file_deletions(
                std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
                10,
            )
            .await
            .expect("pending");
        assert!(!pending
            .iter()
            .any(|item| item.space_id == space_id && item.file_id == file_id));

        // Tombstone again: while the object awaits grace-period removal it
        // still counts against the quota (its bytes occupy storage until
        // the sweep completes), so a create→delete churn loop cannot cycle
        // past the limit through the grace window.
        storage
            .tombstone_file(space_id, file_id)
            .await
            .expect("second tombstone");
        assert_eq!(
            storage
                .record_file(
                    space_id,
                    uuid::Uuid::new_v4(),
                    record_id,
                    10,
                    &wrapped_dek(8),
                )
                .await
                .unwrap_err(),
            StorageError::QuotaExceeded
        );

        // Once the sweep completes the deletion (queue row removed, object
        // gone), the slot frees for a different id.
        storage
            .complete_file_deletion(space_id, file_id)
            .await
            .expect("sweep completion");
        storage
            .record_file(
                space_id,
                uuid::Uuid::new_v4(),
                record_id,
                10,
                &wrapped_dek(8),
            )
            .await
            .expect("quota freed after sweep");
    }

    #[tokio::test]
    async fn record_file_roundtrip() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;
        let record_id = create_record(&storage, space_id).await;
        let file_id = uuid::Uuid::new_v4();
        let dek = wrapped_dek(0xfe);

        let cursor = storage
            .record_file(space_id, file_id, record_id, 100, &dek)
            .await
            .expect("record file")
            .expect("should return cursor for new file");
        assert!(cursor > 0);
        let metadata = storage
            .get_file_metadata(space_id, file_id)
            .await
            .expect("get metadata");
        assert_eq!(metadata.id, file_id);
        assert_eq!(metadata.record_id, record_id);
        assert_eq!(metadata.size, 100);
        assert_eq!(metadata.wrapped_dek, dek);
        assert_eq!(metadata.cursor, cursor);
    }

    #[tokio::test]
    async fn record_file_is_idempotent_without_cursor_advance() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;
        let record_id = create_record(&storage, space_id).await;
        let file_id = uuid::Uuid::new_v4();
        let dek = wrapped_dek(0xfe);

        let first_cursor = storage
            .record_file(space_id, file_id, record_id, 100, &dek)
            .await
            .expect("first record file")
            .expect("should return cursor for new file");

        let second_result = storage
            .record_file(space_id, file_id, record_id, 100, &dek)
            .await
            .expect("second record file");
        assert_eq!(second_result, None, "idempotent call should return None");
        let space_cursor = storage.get_space(space_id).await.expect("get space").cursor;
        assert_eq!(space_cursor, first_cursor, "cursor should not advance");
    }

    #[tokio::test]
    async fn record_file_validates_wrapped_dek_and_size() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;
        let record_id = create_record(&storage, space_id).await;

        let invalid_dek = storage
            .record_file(space_id, uuid::Uuid::new_v4(), record_id, 100, b"short")
            .await
            .expect_err("short wrapped dek should fail");
        assert_eq!(invalid_dek, StorageError::InvalidWrappedDek);

        let invalid_size = storage
            .record_file(
                space_id,
                uuid::Uuid::new_v4(),
                record_id,
                -1,
                &wrapped_dek(0xfe),
            )
            .await
            .expect_err("negative file size should fail");
        assert_eq!(invalid_size, StorageError::InvalidFileSize);
    }

    #[tokio::test]
    async fn get_file_metadata_not_found() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let error = storage
            .get_file_metadata(space_id, uuid::Uuid::new_v4())
            .await
            .expect_err("missing file should fail");
        assert_eq!(error, StorageError::FileNotFound);
    }

    #[tokio::test]
    async fn file_exists_and_isolation() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_a = uuid::Uuid::new_v4();
        let space_b = uuid::Uuid::new_v4();
        create_space(&storage, space_a).await;
        create_space(&storage, space_b).await;
        let record_id = create_record(&storage, space_a).await;
        let file_id = uuid::Uuid::new_v4();
        let dek = wrapped_dek(0xfe);

        let before = storage
            .file_exists(space_a, file_id)
            .await
            .expect("exists before insert");
        assert!(!before);

        storage
            .record_file(space_a, file_id, record_id, 100, &dek)
            .await
            .expect("record file");

        let exists_a = storage
            .file_exists(space_a, file_id)
            .await
            .expect("exists in space a");
        let exists_b = storage
            .file_exists(space_b, file_id)
            .await
            .expect("exists in space b");
        assert!(exists_a);
        assert!(!exists_b);
    }

    #[tokio::test]
    async fn get_file_deks_respects_since_cursor() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;
        let record_id = create_record(&storage, space_id).await;

        let file_a = uuid::Uuid::new_v4();
        let file_b = uuid::Uuid::new_v4();
        storage
            .record_file(space_id, file_a, record_id, 100, &wrapped_dek(0xaa))
            .await
            .expect("record file a");
        let all = storage
            .get_file_deks(space_id, 0)
            .await
            .expect("get all deks");
        assert_eq!(all.len(), 1);
        let first_cursor = all[0].cursor;

        storage
            .record_file(space_id, file_b, record_id, 200, &wrapped_dek(0xbb))
            .await
            .expect("record file b");
        let since = storage
            .get_file_deks(space_id, first_cursor)
            .await
            .expect("get since");
        assert_eq!(since.len(), 1);
        assert_eq!(since[0].id, file_b);
    }

    #[tokio::test]
    async fn rewrap_file_deks_roundtrip() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;
        let record_id = create_record(&storage, space_id).await;
        let file_id = uuid::Uuid::new_v4();

        storage
            .record_file(
                space_id,
                file_id,
                record_id,
                100,
                &wrapped_dek_with_epoch(1, 0xaa),
            )
            .await
            .expect("record file");

        let new_dek = wrapped_dek_with_epoch(1, 0xcc);
        storage
            .rewrap_file_deks(
                space_id,
                &[FileDekRecord {
                    id: file_id,
                    wrapped_dek: new_dek.clone(),
                    cursor: 0,
                    observed_wrapped_dek: None,
                }],
            )
            .await
            .expect("rewrap");

        let metadata = storage
            .get_file_metadata(space_id, file_id)
            .await
            .expect("get metadata");
        assert_eq!(metadata.wrapped_dek, new_dek);
    }

    #[tokio::test]
    async fn rewrap_file_deks_epoch_mismatch() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;
        let record_id = create_record(&storage, space_id).await;
        let file_id = uuid::Uuid::new_v4();

        storage
            .record_file(
                space_id,
                file_id,
                record_id,
                100,
                &wrapped_dek_with_epoch(1, 0xaa),
            )
            .await
            .expect("record file");

        sqlx::query("UPDATE spaces SET epoch = 2 WHERE id = $1")
            .bind(space_id)
            .execute(storage.pool())
            .await
            .expect("advance key generation");

        let error = storage
            .rewrap_file_deks(
                space_id,
                &[FileDekRecord {
                    id: file_id,
                    wrapped_dek: wrapped_dek_with_epoch(1, 0xcc),
                    cursor: 0,
                    observed_wrapped_dek: None,
                }],
            )
            .await
            .expect_err("epoch mismatch should fail");
        assert_eq!(error, StorageError::DekEpochMismatch);
    }

    #[tokio::test]
    async fn rewrap_file_deks_with_stale_observed_wrapper_is_rejected() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;
        let record_id = create_record(&storage, space_id).await;
        let file_id = uuid::Uuid::new_v4();

        storage
            .record_file(
                space_id,
                file_id,
                record_id,
                100,
                &wrapped_dek_with_epoch(1, 0xaa),
            )
            .await
            .expect("record file");

        // The rewrapper read the old wrapper...
        let observed = wrapped_dek_with_epoch(1, 0xaa);
        // ...but a concurrent writer already replaced it.
        let concurrent = wrapped_dek_with_epoch(1, 0x99);
        sqlx::query("UPDATE files SET wrapped_dek = $1 WHERE id = $2")
            .bind(&concurrent)
            .bind(file_id)
            .execute(storage.pool())
            .await
            .expect("simulate concurrent replacement");

        // A stale rewrap must not overwrite the newer wrapper (AUD-026).
        let stale = storage
            .rewrap_file_deks(
                space_id,
                &[FileDekRecord {
                    id: file_id,
                    wrapped_dek: wrapped_dek_with_epoch(1, 0xbb),
                    cursor: 0,
                    observed_wrapped_dek: Some(observed),
                }],
            )
            .await
            .expect_err("stale observed DEK must fail");
        assert_eq!(stale, StorageError::DekConflict);

        // The concurrently installed wrapper is intact.
        let deks = storage
            .get_file_deks(space_id, 0)
            .await
            .expect("get file DEKs");
        assert!(deks.iter().any(|d| d.wrapped_dek == concurrent));

        // A rewrap carrying the up-to-date observation still succeeds.
        storage
            .rewrap_file_deks(
                space_id,
                &[FileDekRecord {
                    id: file_id,
                    wrapped_dek: wrapped_dek_with_epoch(1, 0xbb),
                    cursor: 0,
                    observed_wrapped_dek: Some(concurrent),
                }],
            )
            .await
            .expect("rewrap with fresh observation");
    }

    #[tokio::test]
    async fn rewrap_file_deks_missing_file() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let error = storage
            .rewrap_file_deks(
                space_id,
                &[FileDekRecord {
                    id: uuid::Uuid::new_v4(),
                    wrapped_dek: wrapped_dek_with_epoch(1, 0xcc),
                    cursor: 0,
                    observed_wrapped_dek: None,
                }],
            )
            .await
            .expect_err("missing file should fail");
        assert_eq!(error, StorageError::FileDekNotFound);
    }

    #[tokio::test]
    async fn rewrap_file_deks_empty_is_noop() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        storage
            .rewrap_file_deks(space_id, &[])
            .await
            .expect("empty rewrap should succeed");
    }

    #[tokio::test]
    async fn delete_files_for_records_deletes_and_returns_ids() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;
        let record_id = create_record(&storage, space_id).await;

        let file_a = uuid::Uuid::new_v4();
        let file_b = uuid::Uuid::new_v4();
        storage
            .record_file(space_id, file_a, record_id, 100, &wrapped_dek(0xaa))
            .await
            .expect("record file a");
        storage
            .record_file(space_id, file_b, record_id, 200, &wrapped_dek(0xbb))
            .await
            .expect("record file b");

        let deleted = storage
            .delete_files_for_records(space_id, &[record_id])
            .await
            .expect("delete files");
        let deleted_set = deleted.into_iter().collect::<HashSet<_>>();
        assert_eq!(deleted_set.len(), 2);
        assert!(deleted_set.contains(&file_a));
        assert!(deleted_set.contains(&file_b));

        let exists_a = storage
            .file_exists(space_id, file_a)
            .await
            .expect("exists a");
        let exists_b = storage
            .file_exists(space_id, file_b)
            .await
            .expect("exists b");
        assert!(!exists_a);
        assert!(!exists_b);
    }

    #[tokio::test]
    async fn delete_files_for_records_empty_returns_empty() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let deleted = storage
            .delete_files_for_records(space_id, &[])
            .await
            .expect("empty delete");
        assert!(deleted.is_empty());
    }
}

#[cfg(test)]
mod min_generation_tests {
    use super::super::test_support::*;
    use super::*;

    #[tokio::test]
    async fn record_file_below_min_epoch_is_rejected_for_shared_spaces() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        // Shared space with the minimum generation raised by a rotation.
        storage
            .create_space(space_id, "client-1", Some(&[0xAB; 33]))
            .await
            .expect("create shared space");
        storage
            .advance_epoch(
                space_id,
                2,
                Some(&crate::AdvanceEpochOptions {
                    set_min_epoch: true,
                }),
            )
            .await
            .expect("raise min generation");
        let record_id = create_record(&storage, space_id).await;

        // A stale device's file DEK wrapped at the old epoch is rejected.
        let stale = storage
            .record_file(
                space_id,
                uuid::Uuid::new_v4(),
                record_id,
                10,
                &wrapped_dek_with_epoch(1, 0x01),
            )
            .await
            .expect_err("stale-epoch file DEK must be rejected");
        assert_eq!(stale, StorageError::EpochStale);

        // A current-epoch file DEK is accepted.
        storage
            .record_file(
                space_id,
                uuid::Uuid::new_v4(),
                record_id,
                10,
                &wrapped_dek_with_epoch(2, 0x02),
            )
            .await
            .expect("current-epoch file DEK accepted");
    }
}
