#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};

use less_sync_core::protocol::{Change, Space};
use less_sync_core::validation::{validate_record_id, DEFAULT_MAX_BLOB_SIZE};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{PullEntry, PullEntryKind, PullResult, PushOptions, PushResult, StorageError};

const MAX_RECORDS_LIMIT: usize = 100_000;
const MAX_PUSH_PAYLOAD: i64 = 500 * 1024 * 1024;

#[derive(Clone)]
pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    pub async fn connect(database_url: &str) -> Result<Self, StorageError> {
        let pool = PgPool::connect(database_url)
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(Self { pool })
    }

    #[must_use]
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn ping(&self) -> Result<(), StorageError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(())
    }

    pub async fn get_space(&self, space_id: Uuid) -> Result<Space, StorageError> {
        let row = sqlx::query_as::<_, SpaceRow>(
            r#"
            SELECT
                id,
                client_id,
                root_public_key,
                key_generation,
                min_key_generation,
                metadata_version,
                cursor,
                rewrap_epoch,
                home_server
            FROM spaces
            WHERE id = $1
            "#,
        )
        .bind(space_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| match error {
            sqlx::Error::RowNotFound => StorageError::SpaceNotFound,
            _ => StorageError::Database(error.to_string()),
        })?;

        Ok(row.into())
    }

    pub async fn get_spaces(
        &self,
        space_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Space>, StorageError> {
        if space_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let rows = sqlx::query_as::<_, SpaceRow>(
            r#"
            SELECT
                id,
                client_id,
                root_public_key,
                key_generation,
                min_key_generation,
                metadata_version,
                cursor,
                rewrap_epoch,
                home_server
            FROM spaces
            WHERE id = ANY($1)
            "#,
        )
        .bind(space_ids)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| {
                let id = row.id;
                (id, row.into())
            })
            .collect())
    }

    pub async fn create_space(
        &self,
        space_id: Uuid,
        client_id: &str,
        root_public_key: Option<&[u8]>,
    ) -> Result<Space, StorageError> {
        let root_public_key = root_public_key.map(ToOwned::to_owned);
        let row = sqlx::query_as::<_, SpaceRow>(
            r#"
            INSERT INTO spaces (id, client_id, root_public_key)
            VALUES ($1, $2, $3)
            RETURNING
                id,
                client_id,
                root_public_key,
                key_generation,
                min_key_generation,
                metadata_version,
                cursor,
                rewrap_epoch,
                home_server
            "#,
        )
        .bind(space_id)
        .bind(client_id)
        .bind(root_public_key)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| {
            if is_unique_violation(&error) {
                StorageError::SpaceExists
            } else {
                StorageError::Database(error.to_string())
            }
        })?;

        Ok(row.into())
    }

    pub async fn get_or_create_space(
        &self,
        space_id: Uuid,
        client_id: &str,
    ) -> Result<Space, StorageError> {
        match self.get_space(space_id).await {
            Ok(space) => return Ok(space),
            Err(StorageError::SpaceNotFound) => {}
            Err(error) => return Err(error),
        }

        match self.create_space(space_id, client_id, None).await {
            Ok(space) => Ok(space),
            Err(StorageError::SpaceExists) => self.get_space(space_id).await,
            Err(error) => Err(error),
        }
    }

    pub async fn pull(&self, space_id: Uuid, since: i64) -> Result<PullResult, StorageError> {
        let cursor: i64 = sqlx::query_scalar("SELECT cursor FROM spaces WHERE id = $1")
            .bind(space_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|error| match error {
                sqlx::Error::RowNotFound => StorageError::SpaceNotFound,
                _ => StorageError::Database(error.to_string()),
            })?;

        let rows = sqlx::query_as::<_, RecordPullRow>(
            r#"
            SELECT
                id,
                cursor,
                blob,
                wrapped_dek,
                deleted
            FROM records
            WHERE space_id = $1
              AND cursor > $2
              AND ($2 <> 0 OR deleted = FALSE)
            ORDER BY cursor ASC, id ASC
            "#,
        )
        .bind(space_id)
        .bind(since)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;

        let entries = rows
            .into_iter()
            .map(|row| PullEntry {
                kind: PullEntryKind::Record,
                cursor: row.cursor,
                record: Some(Change {
                    id: row.id.to_string(),
                    blob: row.blob,
                    cursor: row.cursor,
                    wrapped_dek: row.wrapped_dek,
                    deleted: row.deleted,
                }),
                member: None,
                file: None,
            })
            .collect::<Vec<_>>();
        let record_count = entries.len();

        Ok(PullResult {
            entries,
            record_count,
            cursor,
        })
    }

    pub async fn record_exists(
        &self,
        space_id: Uuid,
        record_id: Uuid,
    ) -> Result<bool, StorageError> {
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

    pub async fn push(
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
            let cursor = get_space_cursor_for_update(&mut tx, space_id).await?;
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
        let space_cursor = get_space_cursor_for_update(&mut tx, space_id).await?;

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

    pub async fn close(self) {
        self.pool.close().await;
    }
}

async fn get_space_cursor_for_update(
    tx: &mut Transaction<'_, Postgres>,
    space_id: Uuid,
) -> Result<i64, StorageError> {
    sqlx::query_scalar("SELECT cursor FROM spaces WHERE id = $1 FOR UPDATE")
        .bind(space_id)
        .fetch_one(tx.as_mut())
        .await
        .map_err(|error| match error {
            sqlx::Error::RowNotFound => StorageError::SpaceNotFound,
            _ => StorageError::Database(error.to_string()),
        })
}

#[derive(Debug, sqlx::FromRow)]
struct SpaceRow {
    id: Uuid,
    client_id: String,
    root_public_key: Option<Vec<u8>>,
    key_generation: i32,
    min_key_generation: i32,
    metadata_version: i32,
    cursor: i64,
    rewrap_epoch: Option<i32>,
    home_server: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct SpaceAuthRow {
    root_public_key: Option<Vec<u8>>,
    min_key_generation: i32,
}

#[derive(Debug, sqlx::FromRow)]
struct ExistingRecordRow {
    id: Uuid,
    cursor: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct RecordPullRow {
    id: Uuid,
    cursor: i64,
    blob: Option<Vec<u8>>,
    wrapped_dek: Option<Vec<u8>>,
    deleted: bool,
}

impl From<SpaceRow> for Space {
    fn from(value: SpaceRow) -> Self {
        Self {
            id: value.id.to_string(),
            client_id: value.client_id,
            root_public_key: value.root_public_key,
            key_generation: value.key_generation,
            min_key_generation: value.min_key_generation,
            metadata_version: value.metadata_version,
            cursor: value.cursor,
            rewrap_epoch: value.rewrap_epoch,
            home_server: value.home_server,
        }
    }
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(db_error) if db_error.code().as_deref() == Some("23505")
    )
}

#[cfg(test)]
mod tests {
    use std::env;

    use less_sync_core::protocol::Change;
    use sqlx::postgres::PgPoolOptions;

    use super::PostgresStorage;

    async fn test_storage() -> Option<PostgresStorage> {
        let database_url = match env::var("DATABASE_URL") {
            Ok(value) => value,
            Err(_) => return None,
        };
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("connect test database");
        crate::migrate_with_pool(&pool)
            .await
            .expect("apply migrations");
        Some(PostgresStorage::from_pool(pool))
    }

    async fn cleanup_space(storage: &PostgresStorage, space_id: uuid::Uuid) {
        let _ = sqlx::query("DELETE FROM spaces WHERE id = $1")
            .bind(space_id)
            .execute(storage.pool())
            .await;
    }

    async fn create_space(storage: &PostgresStorage, space_id: uuid::Uuid) {
        storage
            .create_space(space_id, "client-1", None)
            .await
            .expect("create space");
    }

    fn change(id: &str, blob: Option<&[u8]>, cursor: i64) -> Change {
        Change {
            id: id.to_owned(),
            blob: blob.map(ToOwned::to_owned),
            cursor,
            wrapped_dek: None,
            deleted: false,
        }
    }

    #[tokio::test]
    async fn create_and_get_space_roundtrip() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();

        let created = storage
            .create_space(space_id, "client-1", Some(&[1, 2, 3]))
            .await
            .expect("create space");
        let fetched = storage.get_space(space_id).await.expect("get space");

        assert_eq!(created.id, fetched.id);
        assert_eq!(fetched.id, space_id.to_string());
        assert_eq!(fetched.client_id, "client-1");
        assert_eq!(fetched.root_public_key, Some(vec![1, 2, 3]));

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn get_space_returns_not_found() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let missing = uuid::Uuid::new_v4();

        let error = storage
            .get_space(missing)
            .await
            .expect_err("missing space should fail");
        assert_eq!(error, crate::StorageError::SpaceNotFound);
    }

    #[tokio::test]
    async fn create_space_conflict_returns_space_exists() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();

        storage
            .create_space(space_id, "client-1", None)
            .await
            .expect("create first space");
        let error = storage
            .create_space(space_id, "client-1", None)
            .await
            .expect_err("duplicate insert should fail");
        assert_eq!(error, crate::StorageError::SpaceExists);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn get_or_create_space_is_idempotent() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();

        let first = storage
            .get_or_create_space(space_id, "client-1")
            .await
            .expect("create");
        let second = storage
            .get_or_create_space(space_id, "client-1")
            .await
            .expect("get existing");
        assert_eq!(first.id, second.id);
        assert_eq!(second.root_public_key, None);

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM spaces WHERE id = $1")
            .bind(space_id)
            .fetch_one(storage.pool())
            .await
            .expect("count rows");
        assert_eq!(count, 1);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn get_spaces_omits_missing_ids() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_a = uuid::Uuid::new_v4();
        let space_b = uuid::Uuid::new_v4();
        let missing = uuid::Uuid::new_v4();

        storage
            .create_space(space_a, "client-a", None)
            .await
            .expect("create a");
        storage
            .create_space(space_b, "client-b", None)
            .await
            .expect("create b");

        let spaces = storage
            .get_spaces(&[space_a, space_b, missing])
            .await
            .expect("get spaces");
        assert_eq!(spaces.len(), 2);
        assert!(spaces.contains_key(&space_a));
        assert!(spaces.contains_key(&space_b));
        assert!(!spaces.contains_key(&missing));

        cleanup_space(&storage, space_a).await;
        cleanup_space(&storage, space_b).await;
    }

    #[tokio::test]
    async fn pull_empty_space() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let result = storage.pull(space_id, 0).await.expect("pull empty");
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
            .pull(uuid::Uuid::new_v4(), 0)
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

        let pulled = storage.pull(space_id, 0).await.expect("pull");
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

        let since_one = storage.pull(space_id, 1).await.expect("pull since 1");
        assert_eq!(since_one.records().len(), 1);
        assert!(since_one.records()[0].is_deleted());

        let initial = storage.pull(space_id, 0).await.expect("initial pull");
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
}
