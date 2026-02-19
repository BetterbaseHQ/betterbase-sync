use async_trait::async_trait;
use less_sync_core::protocol::Change;
use less_sync_core::protocol::Space;
use less_sync_storage::{
    AdvanceEpochOptions, AdvanceEpochResult, AppendLogResult, Invitation, MembersLogEntry,
    PullResult, PushResult, Storage, StorageError,
};
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

    async fn append_member(
        &self,
        space_id: Uuid,
        expected_version: i32,
        entry: &MembersLogEntry,
    ) -> Result<AppendLogResult, StorageError>;

    async fn get_members(
        &self,
        space_id: Uuid,
        since_seq: i32,
    ) -> Result<Vec<MembersLogEntry>, StorageError>;

    async fn revoke_ucan(&self, space_id: Uuid, ucan_cid: &str) -> Result<(), StorageError>;

    async fn create_invitation(&self, invitation: &Invitation) -> Result<Invitation, StorageError>;

    async fn list_invitations(
        &self,
        mailbox_id: &str,
        limit: usize,
        after: Option<Uuid>,
    ) -> Result<Vec<Invitation>, StorageError>;

    async fn get_invitation(&self, id: Uuid, mailbox_id: &str) -> Result<Invitation, StorageError>;

    async fn delete_invitation(&self, id: Uuid, mailbox_id: &str) -> Result<(), StorageError>;

    async fn advance_epoch(
        &self,
        space_id: Uuid,
        requested_epoch: i32,
        opts: Option<&AdvanceEpochOptions>,
    ) -> Result<AdvanceEpochResult, StorageError>;

    async fn complete_rewrap(&self, space_id: Uuid, epoch: i32) -> Result<(), StorageError>;
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

    async fn append_member(
        &self,
        space_id: Uuid,
        expected_version: i32,
        entry: &MembersLogEntry,
    ) -> Result<AppendLogResult, StorageError> {
        Storage::append_member(self, space_id, expected_version, entry).await
    }

    async fn get_members(
        &self,
        space_id: Uuid,
        since_seq: i32,
    ) -> Result<Vec<MembersLogEntry>, StorageError> {
        Storage::get_members(self, space_id, since_seq).await
    }

    async fn revoke_ucan(&self, space_id: Uuid, ucan_cid: &str) -> Result<(), StorageError> {
        Storage::revoke_ucan(self, space_id, ucan_cid).await
    }

    async fn create_invitation(&self, invitation: &Invitation) -> Result<Invitation, StorageError> {
        Storage::create_invitation(self, invitation).await
    }

    async fn list_invitations(
        &self,
        mailbox_id: &str,
        limit: usize,
        after: Option<Uuid>,
    ) -> Result<Vec<Invitation>, StorageError> {
        Storage::list_invitations(self, mailbox_id, limit, after).await
    }

    async fn get_invitation(&self, id: Uuid, mailbox_id: &str) -> Result<Invitation, StorageError> {
        Storage::get_invitation(self, id, mailbox_id).await
    }

    async fn delete_invitation(&self, id: Uuid, mailbox_id: &str) -> Result<(), StorageError> {
        Storage::delete_invitation(self, id, mailbox_id).await
    }

    async fn advance_epoch(
        &self,
        space_id: Uuid,
        requested_epoch: i32,
        opts: Option<&AdvanceEpochOptions>,
    ) -> Result<AdvanceEpochResult, StorageError> {
        Storage::advance_epoch(self, space_id, requested_epoch, opts).await
    }

    async fn complete_rewrap(&self, space_id: Uuid, epoch: i32) -> Result<(), StorageError> {
        Storage::complete_rewrap(self, space_id, epoch).await
    }
}
