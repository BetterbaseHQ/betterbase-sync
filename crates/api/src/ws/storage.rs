use async_trait::async_trait;
use less_sync_core::protocol::Change;
use less_sync_core::protocol::Space;
use less_sync_storage::{PullResult, PushResult, Storage, StorageError};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SubscribedSpaceState {
    pub cursor: i64,
    pub key_generation: i32,
    pub rewrap_epoch: Option<i32>,
}

#[async_trait]
pub(crate) trait SyncStorage: Send + Sync {
    async fn get_space(&self, space_id: Uuid) -> Result<Space, StorageError>;
    async fn create_space(
        &self,
        space_id: Uuid,
        client_id: &str,
        root_public_key: Option<&[u8]>,
    ) -> Result<Space, StorageError>;

    async fn get_or_create_space(
        &self,
        space_id: Uuid,
        client_id: &str,
    ) -> Result<SubscribedSpaceState, StorageError>;

    async fn push(&self, space_id: Uuid, changes: &[Change]) -> Result<PushResult, StorageError>;

    async fn pull(&self, space_id: Uuid, since: i64) -> Result<PullResult, StorageError>;
}

#[async_trait]
impl<T> SyncStorage for T
where
    T: Storage + Send + Sync,
{
    async fn get_space(&self, space_id: Uuid) -> Result<Space, StorageError> {
        Storage::get_space(self, space_id).await
    }

    async fn create_space(
        &self,
        space_id: Uuid,
        client_id: &str,
        root_public_key: Option<&[u8]>,
    ) -> Result<Space, StorageError> {
        Storage::create_space(self, space_id, client_id, root_public_key).await
    }

    async fn get_or_create_space(
        &self,
        space_id: Uuid,
        client_id: &str,
    ) -> Result<SubscribedSpaceState, StorageError> {
        let space = Storage::get_or_create_space(self, space_id, client_id).await?;
        Ok(SubscribedSpaceState {
            cursor: space.cursor,
            key_generation: space.key_generation,
            rewrap_epoch: space.rewrap_epoch,
        })
    }

    async fn push(&self, space_id: Uuid, changes: &[Change]) -> Result<PushResult, StorageError> {
        Storage::push(self, space_id, changes, None).await
    }

    async fn pull(&self, space_id: Uuid, since: i64) -> Result<PullResult, StorageError> {
        Storage::pull(self, space_id, since).await
    }
}
