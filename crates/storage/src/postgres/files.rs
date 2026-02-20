use async_trait::async_trait;
use uuid::Uuid;

use super::PostgresStorage;
use crate::{FileDekRecord, FileMetadata, FileStorage, StorageError};

pub(super) const WRAPPED_DEK_LENGTH: usize = 44;

#[async_trait]
impl FileStorage for PostgresStorage {
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

        let new_cursor: i64 = sqlx::query_scalar(
            "UPDATE spaces SET cursor = cursor + 1 WHERE id = $1 RETURNING cursor",
        )
        .bind(space_id)
        .fetch_one(tx.as_mut())
        .await
        .map_err(|error| match error {
            sqlx::Error::RowNotFound => StorageError::SpaceNotFound,
            _ => StorageError::Database(error.to_string()),
        })?;

        let result = sqlx::query(
            r#"
            INSERT INTO files (space_id, id, record_id, size, wrapped_dek, cursor)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (space_id, id) DO NOTHING
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

        // Preserve idempotency without advancing space cursor when the file already exists.
        if result.rows_affected() == 0 {
            tx.rollback()
                .await
                .map_err(|error| StorageError::Database(error.to_string()))?;
            return Ok(None);
        }

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
            WHERE space_id = $1 AND id = $2
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
            "SELECT EXISTS(SELECT 1 FROM files WHERE space_id = $1 AND id = $2)",
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

        let key_generation: i32 =
            sqlx::query_scalar("SELECT key_generation FROM spaces WHERE id = $1 FOR UPDATE")
                .bind(space_id)
                .fetch_one(tx.as_mut())
                .await
                .map_err(|error| match error {
                    sqlx::Error::RowNotFound => StorageError::SpaceNotFound,
                    _ => StorageError::Database(error.to_string()),
                })?;

        for dek in deks {
            let epoch =
                super::parse_dek_epoch(&dek.wrapped_dek).ok_or(StorageError::DekEpochMismatch)?;
            if epoch != key_generation {
                return Err(StorageError::DekEpochMismatch);
            }
        }

        for dek in deks {
            let result =
                sqlx::query("UPDATE files SET wrapped_dek = $1 WHERE id = $2 AND space_id = $3")
                    .bind(&dek.wrapped_dek)
                    .bind(dek.id)
                    .bind(space_id)
                    .execute(tx.as_mut())
                    .await
                    .map_err(|error| StorageError::Database(error.to_string()))?;

            if result.rows_affected() != 1 {
                return Err(StorageError::FileDekNotFound);
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
    use crate::{FileDekRecord, FileStorage, SpaceStorage, StorageError};

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

        cleanup_space(&storage, space_id).await;
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

        cleanup_space(&storage, space_id).await;
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

        cleanup_space(&storage, space_id).await;
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

        cleanup_space(&storage, space_id).await;
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

        cleanup_space(&storage, space_a).await;
        cleanup_space(&storage, space_b).await;
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

        cleanup_space(&storage, space_id).await;
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
                }],
            )
            .await
            .expect("rewrap");

        let metadata = storage
            .get_file_metadata(space_id, file_id)
            .await
            .expect("get metadata");
        assert_eq!(metadata.wrapped_dek, new_dek);

        cleanup_space(&storage, space_id).await;
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

        sqlx::query("UPDATE spaces SET key_generation = 2 WHERE id = $1")
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
                }],
            )
            .await
            .expect_err("epoch mismatch should fail");
        assert_eq!(error, StorageError::DekEpochMismatch);

        cleanup_space(&storage, space_id).await;
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
                }],
            )
            .await
            .expect_err("missing file should fail");
        assert_eq!(error, StorageError::FileDekNotFound);

        cleanup_space(&storage, space_id).await;
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

        cleanup_space(&storage, space_id).await;
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

        cleanup_space(&storage, space_id).await;
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

        cleanup_space(&storage, space_id).await;
    }
}
