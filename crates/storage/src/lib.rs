#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::time::SystemTime;

use async_trait::async_trait;
use betterbase_sync_core::protocol::{Change, Space};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

pub mod postgres;

pub use postgres::PostgresStorage;

/// Computes an HMAC-SHA256 of `(issuer, user_id)` used for ephemeral rate limiting.
/// A null separator protects issuer/user boundary collisions.
#[must_use]
pub fn rate_limit_hash(key: &[u8], issuer: &str, user_id: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of any size for SHA-256");
    mac.update(issuer.as_bytes());
    mac.update(&[0x00]);
    mac.update(user_id.as_bytes());
    let digest = mac.finalize().into_bytes();

    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum StorageError {
    #[error("space not found")]
    SpaceNotFound,
    #[error("space already exists")]
    SpaceExists,
    #[error("file not found")]
    FileNotFound,
    #[error("invitation not found")]
    InvitationNotFound,
    #[error("metadata version conflict")]
    VersionConflict,
    #[error("hash chain broken")]
    HashChainBroken,
    #[error("key generation stale")]
    KeyGenerationStale,
    #[error("epoch mismatch")]
    EpochMismatch,
    #[error("{0}")]
    EpochConflict(EpochConflict),
    #[error("DEK epoch mismatch")]
    DekEpochMismatch,
    #[error("DEK record not found")]
    DekRecordNotFound,
    #[error("file DEK record not found")]
    FileDekNotFound,
    #[error("record not found")]
    RecordNotFound,
    #[error("federation key not found")]
    FederationKeyNotFound,
    #[error("invalid record ID")]
    InvalidRecordId,
    #[error("duplicate record ID in push")]
    DuplicateRecordId,
    #[error("blob exceeds limit")]
    BlobTooLarge,
    #[error("push exceeds record limit")]
    PushRecordLimitExceeded,
    #[error("push exceeds payload limit")]
    PushPayloadLimitExceeded,
    #[error("wrapped DEK must be exactly 44 bytes")]
    InvalidWrappedDek,
    #[error("file size must be non-negative")]
    InvalidFileSize,
    #[error("storage unavailable")]
    Unavailable,
    #[error("database error: {0}")]
    Database(String),
    #[error("migration error: {0}")]
    Migration(String),
    #[error("DATABASE_URL is not set")]
    MissingDatabaseUrl,
}

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMetadata {
    pub id: Uuid,
    pub record_id: Uuid,
    pub size: i64,
    pub wrapped_dek: Vec<u8>,
    pub cursor: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDekRecord {
    pub id: Uuid,
    pub wrapped_dek: Vec<u8>,
    pub cursor: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullEntryKind {
    Record,
    Membership,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullEntry {
    pub kind: PullEntryKind,
    pub cursor: i64,
    pub record: Option<Change>,
    pub member: Option<MembersLogEntry>,
    pub file: Option<FileEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullResult {
    pub entries: Vec<PullEntry>,
    pub record_count: usize,
    pub cursor: i64,
}

impl PullResult {
    #[must_use]
    pub fn records(&self) -> Vec<Change> {
        self.entries
            .iter()
            .filter_map(|entry| {
                if entry.kind == PullEntryKind::Record {
                    entry.record.clone()
                } else {
                    None
                }
            })
            .collect()
    }

    #[must_use]
    pub fn members(&self) -> Vec<MembersLogEntry> {
        self.entries
            .iter()
            .filter_map(|entry| {
                if entry.kind == PullEntryKind::Membership {
                    entry.member.clone()
                } else {
                    None
                }
            })
            .collect()
    }

    #[must_use]
    pub fn files(&self) -> Vec<FileEntry> {
        self.entries
            .iter()
            .filter_map(|entry| {
                if entry.kind == PullEntryKind::File {
                    entry.file.clone()
                } else {
                    None
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullStreamMeta {
    pub cursor: i64,
    pub key_generation: i32,
    pub rewrap_epoch: Option<i32>,
}

/// A streaming pull result. Entries are delivered one at a time via a channel
/// from a background task that streams rows from the DB cursor — O(1) memory.
#[derive(Debug)]
pub struct PullStream {
    pub meta: PullStreamMeta,
    entries_rx: tokio::sync::mpsc::Receiver<Result<PullEntry, StorageError>>,
}

impl PullStream {
    pub fn new(
        meta: PullStreamMeta,
        entries_rx: tokio::sync::mpsc::Receiver<Result<PullEntry, StorageError>>,
    ) -> Self {
        Self { meta, entries_rx }
    }

    /// Receive the next entry from the stream.
    pub async fn next(&mut self) -> Option<Result<PullEntry, StorageError>> {
        self.entries_rx.recv().await
    }

    /// Collect all entries into a `PullResult`. Useful for tests.
    pub async fn collect(mut self) -> Result<PullResult, StorageError> {
        let mut entries = Vec::new();
        let mut record_count = 0;
        while let Some(entry) = self.entries_rx.recv().await {
            let entry = entry?;
            if entry.kind == PullEntryKind::Record {
                record_count += 1;
            }
            entries.push(entry);
        }
        Ok(PullResult {
            entries,
            record_count,
            cursor: self.meta.cursor,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub id: Uuid,
    pub record_id: Uuid,
    pub size: i64,
    pub deleted: bool,
    pub wrapped_dek: Vec<u8>,
    pub cursor: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushResult {
    pub ok: bool,
    pub cursor: i64,
    pub deleted_file_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    pub id: Uuid,
    pub mailbox_id: String,
    pub payload: Vec<u8>,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushOptions {
    pub key_generation: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembersLogEntry {
    pub space_id: Uuid,
    pub chain_seq: i32,
    pub cursor: i64,
    pub prev_hash: Vec<u8>,
    pub entry_hash: Vec<u8>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendLogResult {
    pub chain_seq: i32,
    pub cursor: i64,
    pub metadata_version: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvanceEpochOptions {
    pub set_min_key_generation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvanceEpochResult {
    pub epoch: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochConflict {
    pub current_epoch: i32,
    pub rewrap_epoch: Option<i32>,
}

impl std::fmt::Display for EpochConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.rewrap_epoch.is_some() {
            f.write_str("epoch conflict: rewrap in progress")
        } else {
            f.write_str("epoch conflict: epoch mismatch")
        }
    }
}

impl std::error::Error for EpochConflict {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationKey {
    pub kid: String,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationSigningKey {
    pub kid: String,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DekRecord {
    pub id: String,
    pub wrapped_dek: Vec<u8>,
    pub cursor: i64,
}

// ---------------------------------------------------------------------------
// Domain-specific storage traits
// ---------------------------------------------------------------------------

#[async_trait]
pub trait SpaceStorage: Send + Sync {
    async fn ping(&self) -> Result<(), StorageError>;
    async fn get_space(&self, space_id: Uuid) -> Result<Space, StorageError>;
    async fn get_spaces(&self, space_ids: &[Uuid]) -> Result<HashMap<Uuid, Space>, StorageError>;
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
    ) -> Result<Space, StorageError>;
}

#[async_trait]
pub trait RecordStorage: Send + Sync {
    /// Stream pull entries from the DB cursor. Returns a `PullStream` that yields
    /// entries one at a time via a channel — O(1) memory regardless of result size.
    async fn stream_pull(&self, space_id: Uuid, since: i64) -> Result<PullStream, StorageError>;
    async fn push(
        &self,
        space_id: Uuid,
        changes: &[Change],
        opts: Option<&PushOptions>,
    ) -> Result<PushResult, StorageError>;
    async fn record_exists(&self, space_id: Uuid, record_id: Uuid) -> Result<bool, StorageError>;
}

#[async_trait]
pub trait FileStorage: Send + Sync {
    /// Records file metadata and advances the space cursor.
    /// Returns `Some(cursor)` when a new record is created, `None` when the file already exists (idempotent).
    async fn record_file(
        &self,
        space_id: Uuid,
        file_id: Uuid,
        record_id: Uuid,
        size: i64,
        wrapped_dek: &[u8],
    ) -> Result<Option<i64>, StorageError>;
    async fn get_file_metadata(
        &self,
        space_id: Uuid,
        file_id: Uuid,
    ) -> Result<FileMetadata, StorageError>;
    async fn file_exists(&self, space_id: Uuid, file_id: Uuid) -> Result<bool, StorageError>;
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
    async fn delete_files_for_records(
        &self,
        space_id: Uuid,
        record_ids: &[Uuid],
    ) -> Result<Vec<Uuid>, StorageError>;
}

#[async_trait]
pub trait RevocationStorage: Send + Sync {
    async fn is_revoked(&self, space_id: Uuid, ucan_cid: &str) -> Result<bool, StorageError>;
    /// Revoke a UCAN by CID. Idempotent — revoking an already-revoked CID is a no-op.
    async fn revoke_ucan(&self, space_id: Uuid, ucan_cid: &str) -> Result<(), StorageError>;
}

#[async_trait]
pub trait InvitationStorage: Send + Sync {
    async fn create_invitation(&self, invitation: &Invitation) -> Result<Invitation, StorageError>;
    async fn list_invitations(
        &self,
        mailbox_id: &str,
        limit: usize,
        after: Option<Uuid>,
    ) -> Result<Vec<Invitation>, StorageError>;
    async fn get_invitation(&self, id: Uuid, mailbox_id: &str) -> Result<Invitation, StorageError>;
    async fn delete_invitation(&self, id: Uuid, mailbox_id: &str) -> Result<(), StorageError>;
    async fn purge_expired_invitations(&self) -> Result<i64, StorageError>;
}

#[async_trait]
pub trait MembershipStorage: Send + Sync {
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
}

#[async_trait]
pub trait EpochStorage: Send + Sync {
    async fn advance_epoch(
        &self,
        space_id: Uuid,
        requested_epoch: i32,
        opts: Option<&AdvanceEpochOptions>,
    ) -> Result<AdvanceEpochResult, StorageError>;
    async fn complete_rewrap(&self, space_id: Uuid, epoch: i32) -> Result<(), StorageError>;
    async fn get_deks(&self, space_id: Uuid, since: i64) -> Result<Vec<DekRecord>, StorageError>;
    async fn rewrap_deks(&self, space_id: Uuid, deks: &[DekRecord]) -> Result<(), StorageError>;
}

#[async_trait]
pub trait RateLimitStorage: Send + Sync {
    async fn count_recent_actions(
        &self,
        action: &str,
        actor_hash: &str,
        since: SystemTime,
    ) -> Result<i64, StorageError>;
    async fn record_action(&self, action: &str, actor_hash: &str) -> Result<(), StorageError>;
    async fn cleanup_expired_actions(&self, before: SystemTime) -> Result<i64, StorageError>;
}

#[async_trait]
pub trait FederationStorage: Send + Sync {
    async fn get_space_home_server(&self, space_id: Uuid) -> Result<Option<String>, StorageError>;
    async fn set_space_home_server(
        &self,
        space_id: Uuid,
        home_server: &str,
    ) -> Result<(), StorageError>;
    async fn ensure_federation_key(
        &self,
        kid: &str,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<(), StorageError>;
    async fn set_federation_primary_key(&self, kid: &str) -> Result<(), StorageError>;
    async fn deactivate_federation_key(&self, kid: &str) -> Result<(), StorageError>;
    async fn get_federation_private_key(&self, kid: &str) -> Result<Vec<u8>, StorageError>;
    async fn get_federation_signing_key(
        &self,
    ) -> Result<Option<FederationSigningKey>, StorageError>;
    async fn list_federation_public_keys(&self) -> Result<Vec<FederationKey>, StorageError>;
}

/// Unified supertrait for code that needs access to all storage domains.
pub trait Storage:
    SpaceStorage
    + RecordStorage
    + FileStorage
    + RevocationStorage
    + InvitationStorage
    + MembershipStorage
    + EpochStorage
    + RateLimitStorage
    + FederationStorage
{
}

impl<T> Storage for T where
    T: SpaceStorage
        + RecordStorage
        + FileStorage
        + RevocationStorage
        + InvitationStorage
        + MembershipStorage
        + EpochStorage
        + RateLimitStorage
        + FederationStorage
{
}

// ---------------------------------------------------------------------------
// Migration helpers
// ---------------------------------------------------------------------------

pub async fn migrate() -> Result<(), StorageError> {
    let database_url =
        std::env::var("DATABASE_URL").map_err(|_| StorageError::MissingDatabaseUrl)?;
    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;
    migrate_with_pool(&pool).await?;
    pool.close().await;
    Ok(())
}

pub async fn migrate_with_pool(pool: &sqlx::PgPool) -> Result<(), StorageError> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|error| StorageError::Migration(error.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::rate_limit_hash;

    #[test]
    fn rate_limit_hash_is_deterministic() {
        let key = b"01234567890123456789012345678901";
        let first = rate_limit_hash(key, "https://accounts.betterbase.dev", "user1");
        let second = rate_limit_hash(key, "https://accounts.betterbase.dev", "user1");
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn rate_limit_hash_changes_with_inputs() {
        let key = b"01234567890123456789012345678901";
        let first = rate_limit_hash(key, "https://accounts.betterbase.dev", "user1");
        let second = rate_limit_hash(key, "https://accounts.betterbase.dev", "user2");
        let third = rate_limit_hash(key, "https://other.example.com", "user1");
        assert_ne!(first, second);
        assert_ne!(first, third);
    }

    #[test]
    fn rate_limit_hash_uses_null_separator() {
        let key = b"01234567890123456789012345678901";
        let first = rate_limit_hash(key, "ab", "c");
        let second = rate_limit_hash(key, "a", "bc");
        assert_ne!(first, second);
    }

    #[test]
    fn rate_limit_hash_changes_with_key() {
        let key_a = b"01234567890123456789012345678901";
        let key_b = b"abcdefghijklmnopqrstuvwxyz012345";
        let first = rate_limit_hash(key_a, "issuer", "user");
        let second = rate_limit_hash(key_b, "issuer", "user");
        assert_ne!(first, second);
    }
}
