#![forbid(unsafe_code)]

use sqlx::PgPool;

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

    pub async fn close(self) {
        self.pool.close().await;
    }
}
