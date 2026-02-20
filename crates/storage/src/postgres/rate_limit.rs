use std::time::SystemTime;

use async_trait::async_trait;

use super::{system_time_to_unix_micros, PostgresStorage};
use crate::{RateLimitStorage, StorageError};

#[async_trait]
impl RateLimitStorage for PostgresStorage {
    async fn count_recent_actions(
        &self,
        action: &str,
        actor_hash: &str,
        since: SystemTime,
    ) -> Result<i64, StorageError> {
        let since_micros = system_time_to_unix_micros(since)?;
        let count = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM rate_limit_actions
            WHERE action = $1
              AND actor_hash = $2
              AND created_at > to_timestamp(($3::double precision) / 1000000.0)
            "#,
        )
        .bind(action)
        .bind(actor_hash)
        .bind(since_micros)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(count)
    }

    async fn record_action(&self, action: &str, actor_hash: &str) -> Result<(), StorageError> {
        sqlx::query("INSERT INTO rate_limit_actions (action, actor_hash) VALUES ($1, $2)")
            .bind(action)
            .bind(actor_hash)
            .execute(&self.pool)
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(())
    }

    async fn cleanup_expired_actions(&self, before: SystemTime) -> Result<i64, StorageError> {
        let before_micros = system_time_to_unix_micros(before)?;
        let result = sqlx::query(
            "DELETE FROM rate_limit_actions WHERE created_at < to_timestamp(($1::double precision) / 1000000.0)",
        )
        .bind(before_micros)
        .execute(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(result.rows_affected() as i64)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::super::test_support::*;

    #[tokio::test]
    async fn rate_limit_actions_lifecycle() {
        let Some(storage) = test_storage().await else {
            return;
        };

        let key = b"01234567890123456789012345678901";
        let hash = crate::rate_limit_hash(key, "issuer", "user1");
        let action = "test_action";
        let before = SystemTime::now() - Duration::from_secs(1);

        let count = storage
            .count_recent_actions(action, &hash, before)
            .await
            .expect("count before");
        assert_eq!(count, 0);

        storage.record_action(action, &hash).await.expect("record");
        storage
            .record_action(action, &hash)
            .await
            .expect("record again");

        let count = storage
            .count_recent_actions(action, &hash, before)
            .await
            .expect("count after");
        assert_eq!(count, 2);

        // Different actor sees zero.
        let other_hash = crate::rate_limit_hash(key, "issuer", "user2");
        let count = storage
            .count_recent_actions(action, &other_hash, before)
            .await
            .expect("count other");
        assert_eq!(count, 0);

        // Cleanup removes old entries.
        let future = SystemTime::now() + Duration::from_secs(60);
        let cleaned = storage
            .cleanup_expired_actions(future)
            .await
            .expect("cleanup");
        assert!(cleaned >= 2);

        let count = storage
            .count_recent_actions(action, &hash, before)
            .await
            .expect("count after cleanup");
        assert_eq!(count, 0);
    }
}
