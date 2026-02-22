use async_trait::async_trait;
use betterbase_sync_core::protocol::Change;
use betterbase_sync_core::protocol::Space;
use std::time::SystemTime;

use betterbase_sync_storage::{
    AdvanceEpochOptions, AdvanceEpochResult, AppendLogResult, DekRecord, EpochStorage,
    FileDekRecord, FileStorage as FileStorageTrait, Invitation, InvitationStorage, MembersLogEntry,
    MembershipStorage, PullStream, PushResult, RateLimitStorage, RecordStorage, RevocationStorage,
    SpaceStorage, Storage, StorageError,
};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SubscribedSpaceState {
    pub cursor: i64,
    pub key_generation: i32,
    pub rewrap_epoch: Option<i32>,
    pub home_server: Option<String>,
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

    async fn stream_pull(&self, space_id: Uuid, since: i64) -> Result<PullStream, StorageError>;

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
    async fn is_revoked(&self, space_id: Uuid, ucan_cid: &str) -> Result<bool, StorageError>;

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

    async fn get_deks(&self, space_id: Uuid, since: i64) -> Result<Vec<DekRecord>, StorageError>;

    async fn rewrap_deks(&self, space_id: Uuid, deks: &[DekRecord]) -> Result<(), StorageError>;

    async fn get_file_deks(
        &self,
        space_id: Uuid,
        since: i64,
    ) -> Result<Vec<FileDekRecord>, StorageError>;

    async fn rewrap_file_deks(
        &self,
        space_id: Uuid,
        deks: &[FileDekRecord],
    ) -> Result<(), StorageError>;

    async fn count_recent_actions(
        &self,
        action: &str,
        actor_hash: &str,
        since: SystemTime,
    ) -> Result<i64, StorageError>;

    async fn record_action(&self, action: &str, actor_hash: &str) -> Result<(), StorageError>;
}

#[async_trait]
impl<T> SyncStorage for T
where
    T: Storage + Send + Sync,
{
    async fn get_space(&self, space_id: Uuid) -> Result<Space, StorageError> {
        SpaceStorage::get_space(self, space_id).await
    }

    async fn create_space(
        &self,
        space_id: Uuid,
        client_id: &str,
        root_public_key: Option<&[u8]>,
    ) -> Result<Space, StorageError> {
        SpaceStorage::create_space(self, space_id, client_id, root_public_key).await
    }

    async fn get_or_create_space(
        &self,
        space_id: Uuid,
        client_id: &str,
    ) -> Result<SubscribedSpaceState, StorageError> {
        let space = SpaceStorage::get_or_create_space(self, space_id, client_id).await?;
        Ok(SubscribedSpaceState {
            cursor: space.cursor,
            key_generation: space.key_generation,
            rewrap_epoch: space.rewrap_epoch,
            home_server: space.home_server,
        })
    }

    async fn push(&self, space_id: Uuid, changes: &[Change]) -> Result<PushResult, StorageError> {
        RecordStorage::push(self, space_id, changes, None).await
    }

    async fn stream_pull(&self, space_id: Uuid, since: i64) -> Result<PullStream, StorageError> {
        RecordStorage::stream_pull(self, space_id, since).await
    }

    async fn append_member(
        &self,
        space_id: Uuid,
        expected_version: i32,
        entry: &MembersLogEntry,
    ) -> Result<AppendLogResult, StorageError> {
        MembershipStorage::append_member(self, space_id, expected_version, entry).await
    }

    async fn get_members(
        &self,
        space_id: Uuid,
        since_seq: i32,
    ) -> Result<Vec<MembersLogEntry>, StorageError> {
        MembershipStorage::get_members(self, space_id, since_seq).await
    }

    async fn revoke_ucan(&self, space_id: Uuid, ucan_cid: &str) -> Result<(), StorageError> {
        RevocationStorage::revoke_ucan(self, space_id, ucan_cid).await
    }

    async fn is_revoked(&self, space_id: Uuid, ucan_cid: &str) -> Result<bool, StorageError> {
        RevocationStorage::is_revoked(self, space_id, ucan_cid).await
    }

    async fn create_invitation(&self, invitation: &Invitation) -> Result<Invitation, StorageError> {
        InvitationStorage::create_invitation(self, invitation).await
    }

    async fn list_invitations(
        &self,
        mailbox_id: &str,
        limit: usize,
        after: Option<Uuid>,
    ) -> Result<Vec<Invitation>, StorageError> {
        InvitationStorage::list_invitations(self, mailbox_id, limit, after).await
    }

    async fn get_invitation(&self, id: Uuid, mailbox_id: &str) -> Result<Invitation, StorageError> {
        InvitationStorage::get_invitation(self, id, mailbox_id).await
    }

    async fn delete_invitation(&self, id: Uuid, mailbox_id: &str) -> Result<(), StorageError> {
        InvitationStorage::delete_invitation(self, id, mailbox_id).await
    }

    async fn advance_epoch(
        &self,
        space_id: Uuid,
        requested_epoch: i32,
        opts: Option<&AdvanceEpochOptions>,
    ) -> Result<AdvanceEpochResult, StorageError> {
        EpochStorage::advance_epoch(self, space_id, requested_epoch, opts).await
    }

    async fn complete_rewrap(&self, space_id: Uuid, epoch: i32) -> Result<(), StorageError> {
        EpochStorage::complete_rewrap(self, space_id, epoch).await
    }

    async fn get_deks(&self, space_id: Uuid, since: i64) -> Result<Vec<DekRecord>, StorageError> {
        EpochStorage::get_deks(self, space_id, since).await
    }

    async fn rewrap_deks(&self, space_id: Uuid, deks: &[DekRecord]) -> Result<(), StorageError> {
        EpochStorage::rewrap_deks(self, space_id, deks).await
    }

    async fn get_file_deks(
        &self,
        space_id: Uuid,
        since: i64,
    ) -> Result<Vec<FileDekRecord>, StorageError> {
        FileStorageTrait::get_file_deks(self, space_id, since).await
    }

    async fn rewrap_file_deks(
        &self,
        space_id: Uuid,
        deks: &[FileDekRecord],
    ) -> Result<(), StorageError> {
        FileStorageTrait::rewrap_file_deks(self, space_id, deks).await
    }

    async fn count_recent_actions(
        &self,
        action: &str,
        actor_hash: &str,
        since: SystemTime,
    ) -> Result<i64, StorageError> {
        RateLimitStorage::count_recent_actions(self, action, actor_hash, since).await
    }

    async fn record_action(&self, action: &str, actor_hash: &str) -> Result<(), StorageError> {
        RateLimitStorage::record_action(self, action, actor_hash).await
    }
}
