use std::collections::HashMap;

use async_trait::async_trait;
use betterbase_sync_core::protocol::Space;
use uuid::Uuid;

use super::{is_unique_violation, PostgresStorage};
use crate::{SpaceStorage, StorageError};

#[async_trait]
impl SpaceStorage for PostgresStorage {
    async fn ping(&self) -> Result<(), StorageError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(())
    }

    async fn get_space(&self, space_id: Uuid) -> Result<Space, StorageError> {
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

    async fn get_spaces(&self, space_ids: &[Uuid]) -> Result<HashMap<Uuid, Space>, StorageError> {
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

    async fn create_space(
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

    async fn get_or_create_space(
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
}

#[derive(Debug, sqlx::FromRow)]
pub(crate) struct SpaceRow {
    pub id: Uuid,
    pub client_id: String,
    pub root_public_key: Option<Vec<u8>>,
    pub key_generation: i32,
    pub min_key_generation: i32,
    pub metadata_version: i32,
    pub cursor: i64,
    pub rewrap_epoch: Option<i32>,
    pub home_server: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::super::test_support::*;

    #[tokio::test]
    async fn create_and_get_space_roundtrip() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();

        let created = storage
            .create_space(space_id, "client-1", None)
            .await
            .expect("create space");
        assert_eq!(created.id, space_id.to_string());
        assert_eq!(created.client_id, "client-1");
        assert!(created.root_public_key.is_none());
        assert_eq!(created.key_generation, 1);
        assert_eq!(created.cursor, 0);

        let fetched = storage.get_space(space_id).await.expect("get space");
        assert_eq!(fetched.id, created.id);
        assert_eq!(fetched.client_id, created.client_id);
        assert_eq!(fetched.cursor, 0);
    }

    #[tokio::test]
    async fn get_space_returns_not_found() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let missing = uuid::Uuid::new_v4();
        let result = storage.get_space(missing).await;
        assert_eq!(result.unwrap_err(), crate::StorageError::SpaceNotFound,);
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
            .expect("first create");
        let duplicate = storage.create_space(space_id, "client-2", None).await;
        assert_eq!(duplicate.unwrap_err(), crate::StorageError::SpaceExists,);
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
            .expect("first get_or_create");
        let second = storage
            .get_or_create_space(space_id, "client-1")
            .await
            .expect("second get_or_create");
        assert_eq!(first.id, second.id);
        assert_eq!(first.client_id, second.client_id);
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
            .create_space(space_a, "a", None)
            .await
            .expect("create a");
        storage
            .create_space(space_b, "b", None)
            .await
            .expect("create b");

        let result = storage
            .get_spaces(&[space_a, space_b, missing])
            .await
            .expect("get spaces");
        assert_eq!(result.len(), 2);
        assert!(result.contains_key(&space_a));
        assert!(result.contains_key(&space_b));
        assert!(!result.contains_key(&missing));
    }
}
