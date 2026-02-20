use async_trait::async_trait;
use uuid::Uuid;

use super::PostgresStorage;
use crate::{FederationKey, FederationSigningKey, FederationStorage, StorageError};

#[async_trait]
impl FederationStorage for PostgresStorage {
    async fn get_space_home_server(&self, space_id: Uuid) -> Result<Option<String>, StorageError> {
        sqlx::query_scalar("SELECT home_server FROM spaces WHERE id = $1")
            .bind(space_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|error| match error {
                sqlx::Error::RowNotFound => StorageError::SpaceNotFound,
                _ => StorageError::Database(error.to_string()),
            })
    }

    async fn set_space_home_server(
        &self,
        space_id: Uuid,
        home_server: &str,
    ) -> Result<(), StorageError> {
        let result = sqlx::query("UPDATE spaces SET home_server = $2 WHERE id = $1")
            .bind(space_id)
            .bind(home_server)
            .execute(&self.pool)
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        if result.rows_affected() == 0 {
            return Err(StorageError::SpaceNotFound);
        }
        Ok(())
    }

    async fn ensure_federation_key(
        &self,
        kid: &str,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO federation_signing_keys (kid, private_key, public_key, is_active, is_primary)
            VALUES (
                $1,
                $2,
                $3,
                TRUE,
                NOT EXISTS (
                    SELECT 1
                    FROM federation_signing_keys
                    WHERE is_primary = TRUE AND is_active = TRUE
                )
            )
            ON CONFLICT (kid) DO NOTHING
            "#,
        )
        .bind(kid)
        .bind(private_key)
        .bind(public_key)
        .execute(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(())
    }

    async fn set_federation_primary_key(&self, kid: &str) -> Result<(), StorageError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

        sqlx::query(
            "UPDATE federation_signing_keys SET is_primary = FALSE WHERE is_primary = TRUE",
        )
        .execute(tx.as_mut())
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;

        let updated = sqlx::query(
            r#"
            UPDATE federation_signing_keys
            SET is_primary = TRUE, is_active = TRUE, deactivated_at = NULL
            WHERE kid = $1
            "#,
        )
        .bind(kid)
        .execute(tx.as_mut())
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;
        if updated.rows_affected() == 0 {
            return Err(StorageError::FederationKeyNotFound);
        }

        tx.commit()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(())
    }

    async fn deactivate_federation_key(&self, kid: &str) -> Result<(), StorageError> {
        let updated = sqlx::query(
            r#"
            UPDATE federation_signing_keys
            SET is_active = FALSE, is_primary = FALSE, deactivated_at = NOW()
            WHERE kid = $1
            "#,
        )
        .bind(kid)
        .execute(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;
        if updated.rows_affected() == 0 {
            return Err(StorageError::FederationKeyNotFound);
        }
        Ok(())
    }

    async fn get_federation_private_key(&self, kid: &str) -> Result<Vec<u8>, StorageError> {
        sqlx::query_scalar("SELECT private_key FROM federation_signing_keys WHERE kid = $1")
            .bind(kid)
            .fetch_one(&self.pool)
            .await
            .map_err(|error| match error {
                sqlx::Error::RowNotFound => StorageError::FederationKeyNotFound,
                _ => StorageError::Database(error.to_string()),
            })
    }

    async fn get_federation_signing_key(
        &self,
    ) -> Result<Option<FederationSigningKey>, StorageError> {
        let row = sqlx::query_as::<_, FederationSigningKeyRow>(
            r#"
            SELECT kid, private_key, public_key
            FROM federation_signing_keys
            WHERE is_active = TRUE AND is_primary = TRUE
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;

        Ok(row.map(|row| FederationSigningKey {
            kid: row.kid,
            private_key: row.private_key,
            public_key: row.public_key,
        }))
    }

    async fn list_federation_public_keys(&self) -> Result<Vec<FederationKey>, StorageError> {
        let rows = sqlx::query_as::<_, FederationKeyRow>(
            r#"
            SELECT kid, public_key
            FROM federation_signing_keys
            WHERE is_active = TRUE
            ORDER BY created_at ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| FederationKey {
                kid: row.kid,
                public_key: row.public_key,
            })
            .collect())
    }
}

#[derive(Debug, sqlx::FromRow)]
struct FederationKeyRow {
    kid: String,
    public_key: Vec<u8>,
}

#[derive(Debug, sqlx::FromRow)]
struct FederationSigningKeyRow {
    kid: String,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use crate::{FederationStorage, StorageError};

    #[tokio::test]
    async fn space_home_server_roundtrip() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let before = storage
            .get_space_home_server(space_id)
            .await
            .expect("get home server");
        assert_eq!(before, None);

        storage
            .set_space_home_server(space_id, "https://example.test")
            .await
            .expect("set home server");
        let after = storage
            .get_space_home_server(space_id)
            .await
            .expect("get updated home server");
        assert_eq!(after.as_deref(), Some("https://example.test"));

        let missing_get = storage
            .get_space_home_server(uuid::Uuid::new_v4())
            .await
            .expect_err("missing space get should fail");
        assert_eq!(missing_get, StorageError::SpaceNotFound);
        let missing_set = storage
            .set_space_home_server(uuid::Uuid::new_v4(), "https://missing.test")
            .await
            .expect_err("missing space set should fail");
        assert_eq!(missing_set, StorageError::SpaceNotFound);
    }

    #[tokio::test]
    async fn federation_keys_rotation_keeps_overlap_window_and_promotes_new_primary() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let missing = storage
            .get_federation_private_key("fed-missing")
            .await
            .expect_err("missing key should fail");
        assert_eq!(missing, StorageError::FederationKeyNotFound);

        let kid_a = format!("fed-{}", uuid::Uuid::new_v4());
        let kid_b = format!("fed-{}", uuid::Uuid::new_v4());
        let private_a = b"test-private-key-seed-32-bytes!!".to_vec();
        let public_a = b"test-public-key-32-bytes-here!!!".to_vec();
        let private_b = b"second-seed-32-bytes-long!!!!!!".to_vec();
        let public_b = b"second-pub-key-32-bytes-long!!!".to_vec();

        storage
            .ensure_federation_key(&kid_a, &private_a, &public_a)
            .await
            .expect("ensure key a");
        let primary_a = storage
            .get_federation_signing_key()
            .await
            .expect("get primary key a")
            .expect("primary key a exists");
        assert_eq!(primary_a.kid, kid_a);
        assert_eq!(primary_a.private_key, private_a);
        assert_eq!(primary_a.public_key, public_a);

        storage
            .ensure_federation_key(&kid_a, b"different-seed-32-bytes-long!!!!", &public_a)
            .await
            .expect("ensure key a idempotent");
        let got_again = storage
            .get_federation_private_key(&kid_a)
            .await
            .expect("get key a again");
        assert_eq!(got_again, private_a);

        storage
            .ensure_federation_key(&kid_b, &private_b, &public_b)
            .await
            .expect("ensure key b");

        storage
            .set_federation_primary_key(&kid_b)
            .await
            .expect("promote key b");
        let primary_b = storage
            .get_federation_signing_key()
            .await
            .expect("get promoted key b")
            .expect("promoted key b exists");
        assert_eq!(primary_b.kid, kid_b);
        assert_eq!(primary_b.private_key, private_b);
        assert_eq!(primary_b.public_key, public_b);

        // Rotation overlap window: previously active keys remain in JWKS until deactivated.
        let keys = storage
            .list_federation_public_keys()
            .await
            .expect("list federation keys");
        let key_a = keys.iter().find(|key| key.kid == kid_a).cloned();
        let key_b = keys.iter().find(|key| key.kid == kid_b).cloned();
        assert!(key_a.is_some());
        assert!(key_b.is_some());
        assert_eq!(key_a.expect("key a").public_key, public_a);
        assert_eq!(key_b.expect("key b").public_key, public_b);

        storage
            .deactivate_federation_key(&kid_a)
            .await
            .expect("deactivate old key a");
        let active_keys = storage
            .list_federation_public_keys()
            .await
            .expect("list active federation keys");
        assert_eq!(active_keys.len(), 1);
        assert_eq!(active_keys[0].kid, kid_b);
    }

    #[tokio::test]
    async fn federation_key_primary_and_deactivate_validate_target_kid() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let missing_primary = storage
            .set_federation_primary_key("fed-missing")
            .await
            .expect_err("promoting missing key should fail");
        assert_eq!(missing_primary, StorageError::FederationKeyNotFound);

        let missing_deactivate = storage
            .deactivate_federation_key("fed-missing")
            .await
            .expect_err("deactivating missing key should fail");
        assert_eq!(missing_deactivate, StorageError::FederationKeyNotFound);
    }
}
