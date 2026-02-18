#![forbid(unsafe_code)]

use std::collections::HashMap;

use less_sync_core::protocol::Space;
use sqlx::PgPool;
use uuid::Uuid;

use crate::StorageError;

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

    pub async fn close(self) {
        self.pool.close().await;
    }
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
}
