use std::time::SystemTime;

use less_sync_core::protocol::Change;
use sqlx::postgres::PgPoolOptions;

use super::PostgresStorage;
use crate::{Invitation, MembersLogEntry};

// Re-export all domain traits so test modules can `use super::super::test_support::*`
// and have every trait method available on PostgresStorage.
#[allow(unused_imports)]
pub(super) use crate::{
    EpochStorage, FederationStorage, FileStorage, InvitationStorage, MembershipStorage,
    RateLimitStorage, RecordStorage, RevocationStorage, SpaceStorage, Storage, StorageError,
};

pub(super) async fn test_storage() -> Option<PostgresStorage> {
    let database_url = match std::env::var("DATABASE_URL") {
        Ok(value) => value,
        Err(_) => return None,
    };

    // Each test gets its own schema for full isolation when running in parallel.
    let schema = format!("test_{}", uuid::Uuid::new_v4().simple());
    let mut opts: sqlx::postgres::PgConnectOptions =
        database_url.parse().expect("parse DATABASE_URL");
    opts = opts.options([("search_path", schema.as_str())]);
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(opts)
        .await
        .expect("connect test database");
    sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
        .execute(&pool)
        .await
        .expect("create test schema");

    crate::migrate_with_pool(&pool)
        .await
        .expect("apply migrations");
    Some(PostgresStorage::from_pool(pool))
}

pub(super) async fn create_space(storage: &PostgresStorage, space_id: uuid::Uuid) {
    storage
        .create_space(space_id, "client-1", None)
        .await
        .expect("create space");
}

pub(super) fn change(id: &str, blob: Option<&[u8]>, cursor: i64) -> Change {
    Change {
        id: id.to_owned(),
        blob: blob.map(ToOwned::to_owned),
        cursor,
        wrapped_dek: None,
        deleted: false,
    }
}

pub(super) async fn create_record(storage: &PostgresStorage, space_id: uuid::Uuid) -> uuid::Uuid {
    use crate::RecordStorage;
    let record_id = uuid::Uuid::new_v4();
    let id = record_id.to_string();
    storage
        .push(space_id, &[change(&id, Some(b"record"), 0)], None)
        .await
        .expect("create record");
    record_id
}

pub(super) async fn create_record_with_dek(
    storage: &PostgresStorage,
    space_id: uuid::Uuid,
    wrapped_dek: Vec<u8>,
) -> uuid::Uuid {
    use crate::RecordStorage;
    let record_id = uuid::Uuid::new_v4();
    let id = record_id.to_string();
    storage
        .push(
            space_id,
            &[Change {
                id,
                blob: Some(b"record".to_vec()),
                cursor: 0,
                wrapped_dek: Some(wrapped_dek),
                deleted: false,
            }],
            None,
        )
        .await
        .expect("create record with DEK");
    record_id
}

pub(super) fn wrapped_dek(fill: u8) -> Vec<u8> {
    vec![fill; super::files::WRAPPED_DEK_LENGTH]
}

pub(super) fn wrapped_dek_with_epoch(epoch: i32, fill: u8) -> Vec<u8> {
    let mut wrapped = wrapped_dek(fill);
    wrapped[0..4].copy_from_slice(&epoch.to_be_bytes());
    wrapped
}

pub(super) fn mailbox_id() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

pub(super) fn invitation_input(mailbox_id: &str, payload: &[u8]) -> Invitation {
    Invitation {
        id: uuid::Uuid::nil(),
        mailbox_id: mailbox_id.to_owned(),
        payload: payload.to_vec(),
        created_at: SystemTime::UNIX_EPOCH,
        expires_at: SystemTime::UNIX_EPOCH,
    }
}

pub(super) fn member_entry(prev_hash: &[u8], entry_hash: &[u8], payload: &[u8]) -> MembersLogEntry {
    MembersLogEntry {
        space_id: uuid::Uuid::nil(),
        chain_seq: 0,
        cursor: 0,
        prev_hash: prev_hash.to_vec(),
        entry_hash: entry_hash.to_vec(),
        payload: payload.to_vec(),
    }
}
