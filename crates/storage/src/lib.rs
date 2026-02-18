#![forbid(unsafe_code)]

use async_trait::async_trait;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("storage unavailable")]
    Unavailable,
}

#[async_trait]
pub trait Storage: Send + Sync {
    async fn ping(&self) -> Result<(), StorageError>;
}

#[derive(Debug, Default)]
pub struct NoopStorage;

#[async_trait]
impl Storage for NoopStorage {
    async fn ping(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

pub async fn migrate() -> Result<(), StorageError> {
    Ok(())
}
