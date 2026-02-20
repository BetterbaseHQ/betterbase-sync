use async_trait::async_trait;
use uuid::Uuid;

use super::PostgresStorage;
use crate::{RevocationStorage, StorageError};

#[async_trait]
impl RevocationStorage for PostgresStorage {
    async fn is_revoked(&self, space_id: Uuid, ucan_cid: &str) -> Result<bool, StorageError> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM revocations WHERE space_id = $1 AND ucan_cid = $2)",
        )
        .bind(space_id)
        .bind(ucan_cid)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(exists)
    }

    async fn revoke_ucan(&self, space_id: Uuid, ucan_cid: &str) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO revocations (space_id, ucan_cid)
            VALUES ($1, $2)
            ON CONFLICT (space_id, ucan_cid) DO NOTHING
            "#,
        )
        .bind(space_id)
        .bind(ucan_cid)
        .execute(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;

    #[tokio::test]
    async fn revoke_ucan_roundtrip_and_space_isolation() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_a = uuid::Uuid::new_v4();
        let space_b = uuid::Uuid::new_v4();
        create_space(&storage, space_a).await;
        create_space(&storage, space_b).await;

        let cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";

        assert!(!storage
            .is_revoked(space_a, cid)
            .await
            .expect("check revocation"));

        storage
            .revoke_ucan(space_a, cid)
            .await
            .expect("revoke ucan");

        assert!(storage
            .is_revoked(space_a, cid)
            .await
            .expect("check after revoke"));

        // Isolated per space.
        assert!(!storage
            .is_revoked(space_b, cid)
            .await
            .expect("check other space"));

        // Idempotent.
        storage
            .revoke_ucan(space_a, cid)
            .await
            .expect("revoke again");
        assert!(storage
            .is_revoked(space_a, cid)
            .await
            .expect("still revoked"));
    }
}
