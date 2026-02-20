#![forbid(unsafe_code)]

mod epochs;
mod federation;
mod files;
mod invitations;
mod membership;
mod rate_limit;
mod records;
mod revocation;
mod spaces;

#[cfg(test)]
mod test_support;

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

    pub async fn close(self) {
        self.pool.close().await;
    }
}

// ---------------------------------------------------------------------------
// Shared row types and helpers used across multiple domain modules
// ---------------------------------------------------------------------------

use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(crate) async fn get_space_cursor_for_update(
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

pub(crate) fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(db_error) if db_error.code().as_deref() == Some("23505")
    )
}

pub(crate) fn parse_dek_epoch(wrapped_dek: &[u8]) -> Option<i32> {
    let epoch = wrapped_dek
        .get(0..4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(i32::from_be_bytes);
    epoch.filter(|value| *value > 0)
}

use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) fn system_time_to_unix_micros(value: SystemTime) -> Result<i64, StorageError> {
    match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_micros())
            .map_err(|_| StorageError::Database("timestamp out of range".to_owned())),
        Err(error) => {
            let micros = i64::try_from(error.duration().as_micros())
                .map_err(|_| StorageError::Database("timestamp out of range".to_owned()))?;
            Ok(-micros)
        }
    }
}

pub(crate) fn unix_micros_to_system_time(value: i64) -> Result<SystemTime, StorageError> {
    let micros = value.unsigned_abs();
    let duration = Duration::from_micros(micros);
    if value >= 0 {
        Ok(UNIX_EPOCH + duration)
    } else {
        UNIX_EPOCH
            .checked_sub(duration)
            .ok_or_else(|| StorageError::Database("timestamp out of range".to_owned()))
    }
}
