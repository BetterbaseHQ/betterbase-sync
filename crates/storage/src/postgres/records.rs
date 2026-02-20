use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use futures_util::StreamExt;
use less_sync_core::protocol::Change;
use less_sync_core::validation::{validate_record_id, DEFAULT_MAX_BLOB_SIZE};
use uuid::Uuid;

use super::PostgresStorage;
use crate::{
    MembersLogEntry, PullEntry, PullEntryKind, PullStream, PullStreamMeta, PushOptions, PushResult,
    RecordStorage, StorageError,
};

const MAX_RECORDS_LIMIT: usize = 100_000;
const MAX_PUSH_PAYLOAD: i64 = 500 * 1024 * 1024;

const PULL_UNION_QUERY: &str = r#"
    SELECT
        'r' AS kind,
        id,
        cursor,
        blob,
        wrapped_dek,
        NULL::uuid AS record_id,
        NULL::bigint AS size,
        deleted,
        NULL::int AS chain_seq,
        NULL::bytea AS prev_hash,
        NULL::bytea AS entry_hash,
        NULL::bytea AS payload
    FROM records
    WHERE space_id = $1
      AND cursor > $2
      AND ($2 <> 0 OR deleted = FALSE)
    UNION ALL
    SELECT
        'm' AS kind,
        NULL::uuid AS id,
        cursor,
        NULL::bytea AS blob,
        NULL::bytea AS wrapped_dek,
        NULL::uuid AS record_id,
        NULL::bigint AS size,
        FALSE AS deleted,
        chain_seq,
        prev_hash,
        entry_hash,
        payload
    FROM members
    WHERE space_id = $1
      AND cursor > $2
    UNION ALL
    SELECT
        'f' AS kind,
        id,
        cursor,
        NULL::bytea AS blob,
        wrapped_dek,
        record_id,
        size,
        deleted,
        NULL::int AS chain_seq,
        NULL::bytea AS prev_hash,
        NULL::bytea AS entry_hash,
        NULL::bytea AS payload
    FROM files
    WHERE space_id = $1
      AND cursor > $2
      AND ($2 <> 0 OR deleted = FALSE)
    ORDER BY cursor ASC
"#;

fn row_to_pull_entry(row: StreamPullRow, space_id: Uuid) -> Result<PullEntry, StorageError> {
    match row.kind.as_str() {
        "r" => {
            let id = row
                .id
                .ok_or_else(|| StorageError::Database("pull record missing id".to_owned()))?;
            Ok(PullEntry {
                kind: PullEntryKind::Record,
                cursor: row.cursor,
                record: Some(Change {
                    id: id.to_string(),
                    blob: row.blob,
                    cursor: row.cursor,
                    wrapped_dek: row.wrapped_dek,
                    deleted: row.deleted,
                }),
                member: None,
                file: None,
            })
        }
        "m" => Ok(PullEntry {
            kind: PullEntryKind::Membership,
            cursor: row.cursor,
            record: None,
            member: Some(MembersLogEntry {
                space_id,
                chain_seq: row.chain_seq.ok_or_else(|| {
                    StorageError::Database("pull member missing chain_seq".to_owned())
                })?,
                cursor: row.cursor,
                prev_hash: row.prev_hash.unwrap_or_default(),
                entry_hash: row.entry_hash.unwrap_or_default(),
                payload: row.payload.unwrap_or_default(),
            }),
            file: None,
        }),
        "f" => {
            let id = row
                .id
                .ok_or_else(|| StorageError::Database("pull file missing id".to_owned()))?;
            let record_id = row
                .record_id
                .ok_or_else(|| StorageError::Database("pull file missing record_id".to_owned()))?;
            Ok(PullEntry {
                kind: PullEntryKind::File,
                cursor: row.cursor,
                record: None,
                member: None,
                file: Some(crate::FileEntry {
                    id,
                    record_id,
                    size: row.size.unwrap_or_default(),
                    deleted: row.deleted,
                    wrapped_dek: row.wrapped_dek.unwrap_or_default(),
                    cursor: row.cursor,
                }),
            })
        }
        _ => Err(StorageError::Database(format!(
            "unexpected pull row kind: {}",
            row.kind
        ))),
    }
}

#[async_trait]
impl RecordStorage for PostgresStorage {
    async fn stream_pull(&self, space_id: Uuid, since: i64) -> Result<PullStream, StorageError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

        // REPEATABLE READ ensures snapshot consistency across the cursor fetch
        // and the UNION ALL — prevents phantom entries from concurrent writes.
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(tx.as_mut())
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

        let meta_row = sqlx::query_as::<_, PullMetaRow>(
            "SELECT cursor, key_generation, rewrap_epoch FROM spaces WHERE id = $1",
        )
        .bind(space_id)
        .fetch_one(tx.as_mut())
        .await
        .map_err(|error| match error {
            sqlx::Error::RowNotFound => StorageError::SpaceNotFound,
            _ => StorageError::Database(error.to_string()),
        })?;

        let meta = PullStreamMeta {
            cursor: meta_row.cursor,
            key_generation: meta_row.key_generation,
            rewrap_epoch: meta_row.rewrap_epoch,
        };

        // Stream rows from the DB cursor in a background task, sending each
        // entry through a channel. The handler reads entries one at a time —
        // O(1) memory regardless of result set size.
        let (entries_tx, entries_rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            let mut rows = sqlx::query_as::<_, StreamPullRow>(PULL_UNION_QUERY)
                .bind(space_id)
                .bind(since)
                .fetch(tx.as_mut());

            while let Some(row_result) = rows.next().await {
                let entry = match row_result {
                    Ok(row) => row_to_pull_entry(row, space_id),
                    Err(e) => Err(StorageError::Database(e.to_string())),
                };
                if entries_tx.send(entry).await.is_err() {
                    break; // receiver dropped
                }
            }
            // Drop `rows` to release the borrow on `tx`, then commit.
            drop(rows);
            if let Err(e) = tx.commit().await {
                tracing::error!(error = %e, "stream_pull: failed to commit transaction");
            }
        });

        Ok(PullStream::new(meta, entries_rx))
    }

    async fn push(
        &self,
        space_id: Uuid,
        changes: &[Change],
        opts: Option<&PushOptions>,
    ) -> Result<PushResult, StorageError> {
        if changes.is_empty() {
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|error| StorageError::Database(error.to_string()))?;
            let cursor = super::get_space_cursor_for_update(&mut tx, space_id).await?;
            tx.commit()
                .await
                .map_err(|error| StorageError::Database(error.to_string()))?;
            return Ok(PushResult {
                ok: true,
                cursor,
                deleted_file_ids: Vec::new(),
            });
        }

        if changes.len() > MAX_RECORDS_LIMIT {
            return Err(StorageError::PushRecordLimitExceeded);
        }

        let mut total_payload = 0_i64;
        let mut record_ids = Vec::with_capacity(changes.len());
        let mut seen_ids = HashSet::with_capacity(changes.len());
        for change in changes {
            validate_record_id(&change.id).map_err(|_| StorageError::InvalidRecordId)?;
            let record_id =
                Uuid::parse_str(&change.id).map_err(|_| StorageError::InvalidRecordId)?;
            if !seen_ids.insert(record_id) {
                return Err(StorageError::DuplicateRecordId);
            }
            record_ids.push(record_id);

            let blob_len = change.blob.as_ref().map_or(0, |blob| blob.len() as i64);
            if blob_len > DEFAULT_MAX_BLOB_SIZE {
                return Err(StorageError::BlobTooLarge);
            }
            total_payload += blob_len;
        }

        if total_payload > MAX_PUSH_PAYLOAD {
            return Err(StorageError::PushPayloadLimitExceeded);
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        let space_cursor = super::get_space_cursor_for_update(&mut tx, space_id).await?;

        if let Some(opts) = opts {
            if opts.key_generation > 0 {
                let row = sqlx::query_as::<_, SpaceAuthRow>(
                    "SELECT root_public_key, min_key_generation FROM spaces WHERE id = $1",
                )
                .bind(space_id)
                .fetch_one(tx.as_mut())
                .await
                .map_err(|error| StorageError::Database(error.to_string()))?;
                if row.root_public_key.is_some() && opts.key_generation < row.min_key_generation {
                    return Err(StorageError::KeyGenerationStale);
                }
            }
        }

        let existing_rows = sqlx::query_as::<_, ExistingRecordRow>(
            "SELECT id, cursor FROM records WHERE space_id = $1 AND id = ANY($2)",
        )
        .bind(space_id)
        .bind(&record_ids)
        .fetch_all(tx.as_mut())
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;
        let existing_sequences = existing_rows
            .into_iter()
            .map(|row| (row.id, row.cursor))
            .collect::<HashMap<_, _>>();

        for (idx, change) in changes.iter().enumerate() {
            let record_id = record_ids[idx];
            let existing_sequence = existing_sequences.get(&record_id).copied();

            let has_conflict = match (change.cursor, existing_sequence) {
                (0, Some(_)) => true,
                (0, None) => false,
                (_, None) => true,
                (cursor, Some(existing)) => cursor != existing,
            };

            if has_conflict {
                return Ok(PushResult {
                    ok: false,
                    cursor: 0,
                    deleted_file_ids: Vec::new(),
                });
            }
        }

        let new_cursor = space_cursor + 1;
        let mut tombstoned_ids = Vec::new();
        for (idx, change) in changes.iter().enumerate() {
            let record_id = record_ids[idx];
            let deleted = change.blob.is_none();
            if deleted {
                tombstoned_ids.push(record_id);
            }

            if existing_sequences.contains_key(&record_id) {
                sqlx::query(
                    "UPDATE records SET blob = $1, cursor = $2, wrapped_dek = $3, deleted = $4 WHERE id = $5",
                )
                .bind(&change.blob)
                .bind(new_cursor)
                .bind(&change.wrapped_dek)
                .bind(deleted)
                .bind(record_id)
                .execute(tx.as_mut())
                .await
                .map_err(|error| StorageError::Database(error.to_string()))?;
            } else {
                sqlx::query(
                    "INSERT INTO records (id, space_id, blob, cursor, wrapped_dek, deleted) VALUES ($1, $2, $3, $4, $5, $6)",
                )
                .bind(record_id)
                .bind(space_id)
                .bind(&change.blob)
                .bind(new_cursor)
                .bind(&change.wrapped_dek)
                .bind(deleted)
                .execute(tx.as_mut())
                .await
                .map_err(|error| StorageError::Database(error.to_string()))?;
            }
        }

        sqlx::query("UPDATE spaces SET cursor = $1 WHERE id = $2")
            .bind(new_cursor)
            .bind(space_id)
            .execute(tx.as_mut())
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

        let mut deleted_file_ids = Vec::new();
        if !tombstoned_ids.is_empty() {
            let rows = sqlx::query_scalar::<_, Uuid>(
                "DELETE FROM files WHERE space_id = $1 AND record_id = ANY($2) RETURNING id",
            )
            .bind(space_id)
            .bind(&tombstoned_ids)
            .fetch_all(tx.as_mut())
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
            deleted_file_ids.extend(rows);
        }

        tx.commit()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

        Ok(PushResult {
            ok: true,
            cursor: new_cursor,
            deleted_file_ids,
        })
    }

    async fn record_exists(&self, space_id: Uuid, record_id: Uuid) -> Result<bool, StorageError> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM records WHERE space_id = $1 AND id = $2)",
        )
        .bind(space_id)
        .bind(record_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(exists)
    }
}

#[derive(Debug, sqlx::FromRow)]
struct ExistingRecordRow {
    id: Uuid,
    cursor: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct PullMetaRow {
    cursor: i64,
    key_generation: i32,
    rewrap_epoch: Option<i32>,
}

#[derive(Debug, sqlx::FromRow)]
struct StreamPullRow {
    kind: String,
    id: Option<Uuid>,
    cursor: i64,
    blob: Option<Vec<u8>>,
    wrapped_dek: Option<Vec<u8>>,
    record_id: Option<Uuid>,
    size: Option<i64>,
    deleted: bool,
    chain_seq: Option<i32>,
    prev_hash: Option<Vec<u8>>,
    entry_hash: Option<Vec<u8>>,
    payload: Option<Vec<u8>>,
}

#[derive(Debug, sqlx::FromRow)]
struct SpaceAuthRow {
    root_public_key: Option<Vec<u8>>,
    min_key_generation: i32,
}

#[cfg(test)]
mod tests {
    use less_sync_core::protocol::Change;

    use super::super::test_support::*;
    use crate::{PullEntry, PullEntryKind};

    #[tokio::test]
    async fn pull_empty_space() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let result = storage
            .stream_pull(space_id, 0)
            .await
            .expect("stream_pull")
            .collect()
            .await
            .expect("collect");
        assert!(result.records().is_empty());
        assert_eq!(result.cursor, 0);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn pull_space_not_found() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let error = storage
            .stream_pull(uuid::Uuid::new_v4(), 0)
            .await
            .expect_err("missing space");
        assert_eq!(error, crate::StorageError::SpaceNotFound);
    }

    #[tokio::test]
    async fn push_to_existing_space() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let changes = vec![change(
            "019400e8-7b5d-7000-8000-000000000001",
            Some(b"hello"),
            0,
        )];
        let result = storage.push(space_id, &changes, None).await.expect("push");
        assert!(result.ok);
        assert_eq!(result.cursor, 1);

        let space = storage.get_space(space_id).await.expect("get space");
        assert_eq!(space.cursor, 1);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn push_conflict_new_record_exists() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let first = vec![change(
            "019400e8-7b5d-7000-8000-000000000001",
            Some(b"v1"),
            0,
        )];
        storage
            .push(space_id, &first, None)
            .await
            .expect("first push");

        let second = vec![change(
            "019400e8-7b5d-7000-8000-000000000001",
            Some(b"v2"),
            0,
        )];
        let result = storage
            .push(space_id, &second, None)
            .await
            .expect("second push");
        assert!(!result.ok);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn push_update_existing_record() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let create = vec![change(
            "019400e8-7b5d-7000-8000-000000000001",
            Some(b"v1"),
            0,
        )];
        storage.push(space_id, &create, None).await.expect("create");

        let update = vec![change(
            "019400e8-7b5d-7000-8000-000000000001",
            Some(b"v2"),
            1,
        )];
        let result = storage.push(space_id, &update, None).await.expect("update");
        assert!(result.ok);
        assert_eq!(result.cursor, 2);

        let pulled = storage
            .stream_pull(space_id, 0)
            .await
            .expect("stream_pull")
            .collect()
            .await
            .expect("collect");
        assert_eq!(pulled.records().len(), 1);
        assert_eq!(pulled.records()[0].blob, Some(b"v2".to_vec()));

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn push_delete_and_initial_sync_skips_tombstones() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let create = vec![change(
            "019400e8-7b5d-7000-8000-000000000001",
            Some(b"data"),
            0,
        )];
        storage.push(space_id, &create, None).await.expect("create");

        let tombstone = vec![change("019400e8-7b5d-7000-8000-000000000001", None, 1)];
        let result = storage
            .push(space_id, &tombstone, None)
            .await
            .expect("tombstone push");
        assert!(result.ok);

        let since_one = storage
            .stream_pull(space_id, 1)
            .await
            .expect("stream_pull")
            .collect()
            .await
            .expect("collect");
        assert_eq!(since_one.records().len(), 1);
        assert!(since_one.records()[0].is_deleted());

        let initial = storage
            .stream_pull(space_id, 0)
            .await
            .expect("stream_pull")
            .collect()
            .await
            .expect("collect");
        assert!(initial.records().is_empty());

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn record_exists_roundtrip() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let missing = storage
            .record_exists(space_id, uuid::Uuid::new_v4())
            .await
            .expect("exists query");
        assert!(!missing);

        let id = "019400e8-7b5d-7000-8000-000000000001";
        let parsed = uuid::Uuid::parse_str(id).expect("parse id");
        storage
            .push(space_id, &[change(id, Some(b"x"), 0)], None)
            .await
            .expect("push");

        let exists = storage
            .record_exists(space_id, parsed)
            .await
            .expect("exists query");
        assert!(exists);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn push_space_not_found() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let error = storage
            .push(
                uuid::Uuid::new_v4(),
                &[change(
                    "019400e8-7b5d-7000-8000-000000000001",
                    Some(b"hello"),
                    0,
                )],
                None,
            )
            .await
            .expect_err("push to missing space should fail");
        assert_eq!(error, StorageError::SpaceNotFound);
    }

    #[tokio::test]
    async fn push_invalid_record_id() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let error = storage
            .push(space_id, &[change("invalid-id", Some(b"data"), 0)], None)
            .await
            .expect_err("invalid record ID should fail");
        assert_eq!(error, StorageError::InvalidRecordId);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn push_blob_too_large() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let large_blob =
            vec![0u8; (less_sync_core::validation::DEFAULT_MAX_BLOB_SIZE + 1) as usize];
        let error = storage
            .push(
                space_id,
                &[Change {
                    id: "019400e8-7b5d-7000-8000-000000000001".to_owned(),
                    blob: Some(large_blob),
                    cursor: 0,
                    wrapped_dek: None,
                    deleted: false,
                }],
                None,
            )
            .await
            .expect_err("oversized blob should fail");
        assert_eq!(error, StorageError::BlobTooLarge);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn push_duplicate_record_id() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let error = storage
            .push(
                space_id,
                &[
                    change("019400e8-7b5d-7000-8000-000000000001", Some(b"first"), 0),
                    change("019400e8-7b5d-7000-8000-000000000001", Some(b"second"), 0),
                ],
                None,
            )
            .await
            .expect_err("duplicate record ID should fail");
        assert_eq!(error, StorageError::DuplicateRecordId);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn push_empty_changes() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let result = storage
            .push(space_id, &[], None)
            .await
            .expect("empty push should succeed");
        assert!(result.ok);
        assert_eq!(result.cursor, 0);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn push_conflict_record_modified() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let id = "019400e8-7b5d-7000-8000-000000000001";

        // Create record
        storage
            .push(space_id, &[change(id, Some(b"v1"), 0)], None)
            .await
            .expect("create");

        // Update record
        storage
            .push(space_id, &[change(id, Some(b"v2"), 1)], None)
            .await
            .expect("update");

        // Try to update with old cursor
        let result = storage
            .push(space_id, &[change(id, Some(b"v3"), 1)], None)
            .await
            .expect("conflict push");
        assert!(!result.ok);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn push_conflict_record_not_found() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        // Try to update a record that doesn't exist (cursor > 0 implies update)
        let result = storage
            .push(
                space_id,
                &[change(
                    "019400e8-7b5d-7000-8000-000000000001",
                    Some(b"v1"),
                    5,
                )],
                None,
            )
            .await
            .expect("conflict push");
        assert!(!result.ok);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn push_conflict_with_tombstone() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let id = "019400e8-7b5d-7000-8000-000000000001";

        // Create record
        storage
            .push(space_id, &[change(id, Some(b"data"), 0)], None)
            .await
            .expect("create");

        // Delete record (tombstone)
        storage
            .push(space_id, &[change(id, None, 1)], None)
            .await
            .expect("tombstone");

        // Try to create "new" record with same ID (cursor=0) — should conflict
        let result = storage
            .push(space_id, &[change(id, Some(b"new data"), 0)], None)
            .await
            .expect("conflict push");
        assert!(!result.ok);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn push_all_or_nothing() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        // Create a record
        storage
            .push(
                space_id,
                &[change(
                    "019400e8-7b5d-7000-8000-000000000001",
                    Some(b"v1"),
                    0,
                )],
                None,
            )
            .await
            .expect("create first record");

        // Try to push: one valid new record + one conflicting
        let result = storage
            .push(
                space_id,
                &[
                    change("019400e8-7b5d-7000-8000-000000000002", Some(b"new"), 0),
                    change("019400e8-7b5d-7000-8000-000000000001", Some(b"bad"), 0),
                ],
                None,
            )
            .await
            .expect("conflict push");
        assert!(!result.ok);

        // Verify the new record was NOT created (all-or-nothing)
        let pull_result = storage
            .stream_pull(space_id, 0)
            .await
            .expect("stream_pull")
            .collect()
            .await
            .expect("collect");
        assert_eq!(pull_result.records().len(), 1);
        assert_eq!(
            pull_result.records()[0].id,
            "019400e8-7b5d-7000-8000-000000000001"
        );

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn push_multiple_records_same_sequence() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let result = storage
            .push(
                space_id,
                &[
                    change("019400e8-7b5d-7000-8000-000000000001", Some(b"a"), 0),
                    change("019400e8-7b5d-7000-8000-000000000002", Some(b"b"), 0),
                    change("019400e8-7b5d-7000-8000-000000000003", Some(b"c"), 0),
                ],
                None,
            )
            .await
            .expect("push multiple");
        assert!(result.ok);
        assert_eq!(result.cursor, 1);

        let pull_result = storage
            .stream_pull(space_id, 0)
            .await
            .expect("stream_pull")
            .collect()
            .await
            .expect("collect");
        assert_eq!(pull_result.records().len(), 3);
        for record in pull_result.records() {
            assert_eq!(record.cursor, 1);
        }

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn push_tombstone_deletes_files() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        // Push a live record with a wrapped DEK
        let record_id = uuid::Uuid::new_v4();
        let record_id_str = record_id.to_string();
        let dek = wrapped_dek(0xdd);
        storage
            .push(
                space_id,
                &[Change {
                    id: record_id_str.clone(),
                    blob: Some(b"data".to_vec()),
                    cursor: 0,
                    wrapped_dek: Some(dek.clone()),
                    deleted: false,
                }],
                None,
            )
            .await
            .expect("push live record");

        // Upload a file for the record
        let file_id = uuid::Uuid::new_v4();
        let file_dek = wrapped_dek(0xfe);
        storage
            .record_file(space_id, file_id, record_id, 100, &file_dek)
            .await
            .expect("record file");

        // Push tombstone
        let result = storage
            .push(
                space_id,
                &[Change {
                    id: record_id_str,
                    blob: None,
                    cursor: 1,
                    wrapped_dek: Some(dek),
                    deleted: false,
                }],
                None,
            )
            .await
            .expect("push tombstone");
        assert!(result.ok);
        assert_eq!(result.deleted_file_ids.len(), 1);
        assert_eq!(result.deleted_file_ids[0], file_id);

        // Verify file is gone
        let exists = storage
            .file_exists(space_id, file_id)
            .await
            .expect("file exists");
        assert!(!exists);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn space_isolation() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_a = uuid::Uuid::new_v4();
        let space_b = uuid::Uuid::new_v4();
        create_space(&storage, space_a).await;
        create_space(&storage, space_b).await;

        storage
            .push(
                space_a,
                &[change(
                    "019400e8-7b5d-7000-8000-000000000001",
                    Some(b"space a data"),
                    0,
                )],
                None,
            )
            .await
            .expect("push to space a");
        storage
            .push(
                space_b,
                &[change(
                    "019400e8-7b5d-7000-8000-000000000002",
                    Some(b"space b data"),
                    0,
                )],
                None,
            )
            .await
            .expect("push to space b");

        let pull_a = storage
            .stream_pull(space_a, 0)
            .await
            .expect("stream_pull a")
            .collect()
            .await
            .expect("collect a");
        let pull_b = storage
            .stream_pull(space_b, 0)
            .await
            .expect("stream_pull b")
            .collect()
            .await
            .expect("collect b");

        assert_eq!(pull_a.records().len(), 1);
        assert_eq!(pull_b.records().len(), 1);
        assert_eq!(pull_a.records()[0].blob, Some(b"space a data".to_vec()));
        assert_eq!(pull_b.records()[0].blob, Some(b"space b data".to_vec()));

        cleanup_space(&storage, space_a).await;
        cleanup_space(&storage, space_b).await;
    }

    #[tokio::test]
    async fn pull_order_by_sequence_then_id() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        // Push records with IDs in non-sorted order; all at cursor=0 (same sequence)
        storage
            .push(
                space_id,
                &[
                    change("019400e8-7b5d-7000-8000-000000000003", Some(b"z"), 0),
                    change("019400e8-7b5d-7000-8000-000000000001", Some(b"a"), 0),
                    change("019400e8-7b5d-7000-8000-000000000002", Some(b"m"), 0),
                ],
                None,
            )
            .await
            .expect("push");

        let result = storage
            .stream_pull(space_id, 0)
            .await
            .expect("stream_pull")
            .collect()
            .await
            .expect("collect");
        let records = result.records();
        let ids: Vec<&str> = records.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "019400e8-7b5d-7000-8000-000000000001",
                "019400e8-7b5d-7000-8000-000000000002",
                "019400e8-7b5d-7000-8000-000000000003",
            ]
        );

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn stream_pull_returns_unified_ordered_entries() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;
        let record_id = create_record(&storage, space_id).await;

        let member_hash = vec![0x77; 32];
        storage
            .append_member(
                space_id,
                0,
                &member_entry(&[], &member_hash, b"member-entry"),
            )
            .await
            .expect("append member");
        storage
            .record_file(
                space_id,
                uuid::Uuid::new_v4(),
                record_id,
                100,
                &wrapped_dek_with_epoch(1, 0xee),
            )
            .await
            .expect("record file");

        let mut pull_stream = storage.stream_pull(space_id, 0).await.expect("stream_pull");

        assert_eq!(pull_stream.meta.key_generation, 1);
        assert_eq!(pull_stream.meta.rewrap_epoch, None);

        let mut entries = Vec::<PullEntry>::new();
        while let Some(entry) = pull_stream.next().await {
            entries.push(entry.expect("entry"));
        }
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].kind, PullEntryKind::Record);
        assert_eq!(entries[1].kind, PullEntryKind::Membership);
        assert_eq!(entries[2].kind, PullEntryKind::File);
        assert!(entries[0].cursor < entries[1].cursor);
        assert!(entries[1].cursor < entries[2].cursor);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn storage_trait_dispatch_smoke() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let backend: &dyn Storage = &storage;
        let space_id = uuid::Uuid::new_v4();

        backend
            .create_space(space_id, "client-trait", None)
            .await
            .expect("create via trait");
        let fetched = backend.get_space(space_id).await.expect("get via trait");
        assert_eq!(fetched.id, space_id.to_string());
        assert_eq!(fetched.client_id, "client-trait");

        cleanup_space(&storage, space_id).await;
    }
}
