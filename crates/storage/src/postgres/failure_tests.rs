//! Persistence failures must remain errors and leave transactions retryable.
use std::time::{Duration, SystemTime};

use uuid::Uuid;

use super::test_support::*;
use crate::{DekRecord, EpochKeyShare, FileDekRecord};

fn database_error<T>(result: Result<T, StorageError>) {
    match result {
        Err(StorageError::Database(message)) => assert!(!message.is_empty()),
        Err(error) => panic!("expected database error, got {error:?}"),
        Ok(_) => panic!("database failure was reported as success"),
    }
}

#[tokio::test]
async fn closed_pool_fails_space_and_record_operations() {
    let Some(storage) = test_storage().await else {
        return;
    };
    storage.clone().close().await;
    let id = Uuid::new_v4();
    database_error(storage.ping().await);
    database_error(storage.get_space(id).await);
    database_error(storage.get_spaces(&[id]).await);
    database_error(storage.create_space(id, "client", None).await);
    database_error(storage.get_or_create_space(id, "client").await);
    database_error(storage.stream_pull(id, 0).await);
    database_error(
        storage
            .push(id, &[change(&id.to_string(), Some(b"blob"), 0)], None)
            .await,
    );
    database_error(storage.record_exists(id, id).await);
}

#[tokio::test]
async fn closed_pool_fails_file_operations_and_cleanup() {
    let Some(storage) = test_storage().await else {
        return;
    };
    storage.clone().close().await;
    let id = Uuid::new_v4();
    let now = SystemTime::now();
    database_error(storage.lock_file(id, id).await);
    database_error(storage.record_file(id, id, id, 1, &wrapped_dek(1)).await);
    database_error(storage.get_file_metadata(id, id).await);
    database_error(storage.file_exists(id, id).await);
    database_error(storage.get_file_deks(id, 0).await);
    database_error(
        storage
            .rewrap_file_deks(
                id,
                &[FileDekRecord {
                    id,
                    wrapped_dek: wrapped_dek_with_epoch(1, 1),
                    cursor: 0,
                    observed_wrapped_dek: None,
                }],
            )
            .await,
    );
    database_error(storage.delete_files_for_records(id, &[id]).await);
    database_error(storage.schedule_file_deletions(id, &[id]).await);
    database_error(storage.pending_file_deletions(now, 100).await);
    database_error(storage.file_deletion_due(id, id, now).await);
    database_error(storage.clear_file_deletion_if_live(id, id).await);
    database_error(storage.complete_file_deletion(id, id).await);
}

#[tokio::test]
async fn closed_pool_fails_membership_and_epoch_operations() {
    let Some(storage) = test_storage().await else {
        return;
    };
    storage.clone().close().await;
    let id = Uuid::new_v4();
    database_error(
        storage
            .append_member(id, 0, &member_entry(&[], &[1; 32], b"entry"))
            .await,
    );
    database_error(storage.get_members(id, 0).await);
    database_error(storage.advance_epoch(id, 2, None).await);
    database_error(storage.complete_rewrap(id, 2).await);
    database_error(storage.get_deks(id, 0).await);
    database_error(
        storage
            .rewrap_deks(
                id,
                &[DekRecord {
                    id: id.to_string(),
                    wrapped_dek: wrapped_dek_with_epoch(1, 1),
                    cursor: 0,
                    observed_wrapped_dek: None,
                }],
            )
            .await,
    );
    database_error(
        storage
            .put_epoch_key_shares(
                id,
                2,
                &[EpochKeyShare {
                    member_did: "did:key:member".to_owned(),
                    wrapped_key: vec![1; 44],
                }],
            )
            .await,
    );
    database_error(storage.get_epoch_key_share(id, 2, "did:key:member").await);
    database_error(storage.prune_epoch_key_shares(id, 1).await);
}

#[tokio::test]
async fn closed_pool_fails_invitations_revocations_and_rate_limits() {
    let Some(storage) = test_storage().await else {
        return;
    };
    storage.clone().close().await;
    let id = Uuid::new_v4();
    let mailbox = mailbox_id();
    database_error(
        storage
            .create_invitation(&invitation_input(&mailbox, b"encrypted"))
            .await,
    );
    database_error(storage.list_invitations(&mailbox, 10, None).await);
    database_error(storage.get_invitation(id, &mailbox).await);
    database_error(storage.delete_invitation(id, &mailbox).await);
    database_error(storage.purge_expired_invitations().await);
    database_error(storage.is_revoked(id, "cid").await);
    database_error(storage.revoke_ucan(id, "cid").await);
    database_error(
        storage
            .count_recent_actions("invite", "actor", SystemTime::now())
            .await,
    );
    database_error(storage.record_action("invite", "actor").await);
    database_error(storage.cleanup_expired_actions(SystemTime::now()).await);
}

#[tokio::test]
async fn closed_pool_fails_federation_operations() {
    let Some(storage) = test_storage().await else {
        return;
    };
    storage.clone().close().await;
    let id = Uuid::new_v4();
    database_error(storage.get_space_home_server(id).await);
    database_error(storage.set_space_home_server(id, "home.example").await);
    database_error(
        storage
            .ensure_federation_key("key", &[1; 32], &[2; 32])
            .await,
    );
    database_error(storage.set_federation_primary_key("key").await);
    database_error(storage.deactivate_federation_key("key").await);
    database_error(storage.get_federation_private_key("key").await);
    database_error(storage.get_federation_signing_key().await);
    database_error(storage.list_federation_public_keys().await);
}

#[tokio::test]
async fn file_transaction_failures_preserve_cursor_metadata_and_cleanup_intent() {
    // Fail each persistence stage, including the deferred commit. Every failure
    // must preserve all three pieces of state and permit the identical retry.
    let stages = [
        ("ALTER TABLE records RENAME TO unavailable_records", "ALTER TABLE unavailable_records RENAME TO records"),
        ("ALTER TABLE spaces RENAME COLUMN min_epoch TO unavailable_epoch", "ALTER TABLE spaces RENAME COLUMN unavailable_epoch TO min_epoch"),
        ("ALTER TABLE files RENAME TO unavailable_files", "ALTER TABLE unavailable_files RENAME TO files"),
        ("CREATE TRIGGER injected_failure BEFORE UPDATE ON spaces FOR EACH ROW EXECUTE FUNCTION fail_write()", "DROP TRIGGER injected_failure ON spaces"),
        ("CREATE TRIGGER injected_failure BEFORE DELETE ON pending_file_deletions FOR EACH ROW EXECUTE FUNCTION fail_write()", "DROP TRIGGER injected_failure ON pending_file_deletions"),
        ("CREATE CONSTRAINT TRIGGER injected_failure AFTER INSERT ON files DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_write()", "DROP TRIGGER injected_failure ON files"),
    ];
    for (inject, restore) in stages {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space = Uuid::new_v4();
        create_space(&storage, space).await;
        let record = create_record(&storage, space).await;
        let file = Uuid::new_v4();
        let cursor = storage.get_space(space).await.expect("space").cursor;
        storage
            .schedule_file_deletions(space, &[file])
            .await
            .expect("cleanup intent");
        sqlx::query("CREATE FUNCTION fail_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected persistence failure'; END $$")
            .execute(storage.pool()).await.expect("failure function");
        sqlx::query(inject)
            .execute(storage.pool())
            .await
            .expect("inject failure");
        database_error(
            storage
                .record_file(space, file, record, 7, &wrapped_dek(1))
                .await,
        );
        sqlx::query(restore)
            .execute(storage.pool())
            .await
            .expect("restore database");
        assert_eq!(
            storage.get_space(space).await.expect("space").cursor,
            cursor,
            "{inject}"
        );
        assert_eq!(
            storage.get_file_metadata(space, file).await,
            Err(StorageError::FileNotFound),
            "{inject}"
        );
        let cutoff = SystemTime::now() + Duration::from_secs(60);
        assert!(
            storage
                .file_deletion_due(space, file, cutoff)
                .await
                .expect("cleanup intent"),
            "{inject}"
        );
        assert_eq!(
            storage
                .record_file(space, file, record, 7, &wrapped_dek(1))
                .await
                .expect("retry"),
            Some(cursor + 1)
        );
        assert_eq!(
            storage
                .get_file_metadata(space, file)
                .await
                .expect("metadata")
                .size,
            7
        );
        assert!(!storage
            .file_deletion_due(space, file, cutoff)
            .await
            .expect("cleared intent"));
        storage.close().await;
    }
}

#[tokio::test]
async fn mixed_pull_helpers_preserve_each_entry_type_and_cursor() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let space = Uuid::new_v4();
    create_space(&storage, space).await;
    let record = create_record(&storage, space).await;
    let file = Uuid::new_v4();
    storage
        .record_file(space, file, record, 7, &wrapped_dek(1))
        .await
        .expect("file");
    storage
        .append_member(space, 0, &member_entry(&[], &[1; 32], b"member"))
        .await
        .expect("membership");
    let result = storage
        .stream_pull(space, 0)
        .await
        .expect("stream")
        .collect()
        .await
        .expect("pull");
    assert_eq!(result.record_count, 1);
    assert_eq!(result.records().len(), 1);
    assert_eq!(result.records()[0].id, record.to_string());
    assert_eq!(result.files().len(), 1);
    assert_eq!(result.files()[0].id, file);
    assert_eq!(result.files()[0].record_id, record);
    assert_eq!(result.members().len(), 1);
    assert_eq!(result.members()[0].payload, b"member");
    assert_eq!(result.cursor, 3);
    assert_eq!(
        result
            .entries
            .iter()
            .map(|entry| entry.cursor)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    let empty = storage
        .stream_pull(space, result.cursor)
        .await
        .expect("incremental stream")
        .collect()
        .await
        .expect("incremental");
    assert!(empty.records().is_empty());
    assert!(empty.files().is_empty());
    assert!(empty.members().is_empty());
    assert_eq!(empty.cursor, result.cursor);
    storage.close().await;
}

#[tokio::test]
async fn rewrap_transaction_failures_do_not_replace_any_record_or_file_wrapper() {
    for files in [false, true] {
        for stage in ["lookup", "update", "commit"] {
            let Some(storage) = test_storage().await else {
                return;
            };
            let space = Uuid::new_v4();
            create_space(&storage, space).await;
            let old = wrapped_dek_with_epoch(1, 1);
            let new = wrapped_dek_with_epoch(1, 2);
            let record = create_record_with_dek(&storage, space, old.clone()).await;
            let file = Uuid::new_v4();
            storage
                .record_file(space, file, record, 7, &old)
                .await
                .expect("file");
            sqlx::query("CREATE FUNCTION fail_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected persistence failure'; END $$")
                .execute(storage.pool()).await.expect("failure function");
            let table = if files { "files" } else { "records" };
            let (inject, restore) = match stage {
                "lookup" => ("ALTER TABLE spaces RENAME COLUMN epoch TO unavailable_epoch".to_owned(), "ALTER TABLE spaces RENAME COLUMN unavailable_epoch TO epoch".to_owned()),
                "update" => (format!("CREATE TRIGGER injected_failure BEFORE UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION fail_write()"), format!("DROP TRIGGER injected_failure ON {table}")),
                _ => (format!("CREATE CONSTRAINT TRIGGER injected_failure AFTER UPDATE ON {table} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_write()"), format!("DROP TRIGGER injected_failure ON {table}")),
            };
            sqlx::query(&inject)
                .execute(storage.pool())
                .await
                .expect("inject");
            let record_deks = [DekRecord {
                id: record.to_string(),
                wrapped_dek: new.clone(),
                cursor: 0,
                observed_wrapped_dek: Some(old.clone()),
            }];
            let file_deks = [FileDekRecord {
                id: file,
                wrapped_dek: new.clone(),
                cursor: 0,
                observed_wrapped_dek: Some(old.clone()),
            }];
            database_error(if files {
                storage.rewrap_file_deks(space, &file_deks).await
            } else {
                storage.rewrap_deks(space, &record_deks).await
            });
            sqlx::query(&restore)
                .execute(storage.pool())
                .await
                .expect("restore");
            assert_eq!(
                storage.get_deks(space, 0).await.expect("record wrapper")[0].wrapped_dek,
                old
            );
            assert_eq!(
                storage
                    .get_file_metadata(space, file)
                    .await
                    .expect("file wrapper")
                    .wrapped_dek,
                old
            );
            if files {
                storage
                    .rewrap_file_deks(space, &file_deks)
                    .await
                    .expect("retry file");
            } else {
                storage
                    .rewrap_deks(space, &record_deks)
                    .await
                    .expect("retry record");
            }
            assert_eq!(
                storage.get_deks(space, 0).await.expect("record wrapper")[0].wrapped_dek,
                if files { &old } else { &new }.to_vec()
            );
            assert_eq!(
                storage
                    .get_file_metadata(space, file)
                    .await
                    .expect("file wrapper")
                    .wrapped_dek,
                if files { &new } else { &old }.to_vec()
            );
            assert_eq!(storage.get_space(space).await.expect("space").cursor, 2);
            storage.close().await;
        }
    }
}

#[tokio::test]
async fn replacing_epoch_key_shares_rolls_back_deletion_on_insert_or_commit_failure() {
    for stage in ["delete", "insert", "commit", "suppressed_insert"] {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space = Uuid::new_v4();
        create_space(&storage, space).await;
        let old = [EpochKeyShare {
            member_did: "member".to_owned(),
            wrapped_key: vec![1; 44],
        }];
        let new = [EpochKeyShare {
            member_did: "member".to_owned(),
            wrapped_key: vec![2; 44],
        }];
        storage
            .put_epoch_key_shares(space, 2, &old)
            .await
            .expect("original shares");
        sqlx::query("CREATE FUNCTION fail_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected persistence failure'; END $$")
            .execute(storage.pool()).await.expect("failure function");
        sqlx::query("CREATE FUNCTION suppress_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$")
            .execute(storage.pool()).await.expect("suppress function");
        let inject = match stage {
            "delete" => "CREATE TRIGGER injected_failure BEFORE DELETE ON epoch_keys FOR EACH ROW EXECUTE FUNCTION fail_write()",
            "insert" => "CREATE TRIGGER injected_failure BEFORE INSERT ON epoch_keys FOR EACH ROW EXECUTE FUNCTION fail_write()",
            "commit" => "CREATE CONSTRAINT TRIGGER injected_failure AFTER INSERT ON epoch_keys DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_write()",
            _ => "CREATE TRIGGER injected_failure BEFORE INSERT ON epoch_keys FOR EACH ROW EXECUTE FUNCTION suppress_write()",
        };
        sqlx::query(inject)
            .execute(storage.pool())
            .await
            .expect("inject");
        database_error(storage.put_epoch_key_shares(space, 2, &new).await);
        sqlx::query("DROP TRIGGER injected_failure ON epoch_keys")
            .execute(storage.pool())
            .await
            .expect("restore");
        assert_eq!(
            storage
                .get_epoch_key_share(space, 2, "member")
                .await
                .expect("original preserved"),
            old[0].wrapped_key
        );
        storage
            .put_epoch_key_shares(space, 2, &new)
            .await
            .expect("retry");
        assert_eq!(
            storage
                .get_epoch_key_share(space, 2, "member")
                .await
                .expect("replacement"),
            new[0].wrapped_key
        );
        storage.close().await;
    }
}

#[tokio::test]
async fn membership_failures_preserve_hash_chain_cursor_and_version() {
    let stages = [
        ("ALTER TABLE spaces RENAME COLUMN metadata_version TO unavailable_version", "ALTER TABLE spaces RENAME COLUMN unavailable_version TO metadata_version"),
        ("ALTER TABLE members RENAME COLUMN chain_seq TO unavailable_seq", "ALTER TABLE members RENAME COLUMN unavailable_seq TO chain_seq"),
        ("CREATE TRIGGER injected_failure BEFORE UPDATE OF cursor ON spaces FOR EACH ROW EXECUTE FUNCTION fail_write()", "DROP TRIGGER injected_failure ON spaces"),
        ("CREATE TRIGGER injected_failure BEFORE INSERT ON members FOR EACH ROW EXECUTE FUNCTION fail_write()", "DROP TRIGGER injected_failure ON members"),
        ("CREATE TRIGGER injected_failure BEFORE UPDATE OF metadata_version ON spaces FOR EACH ROW EXECUTE FUNCTION fail_write()", "DROP TRIGGER injected_failure ON spaces"),
        ("CREATE CONSTRAINT TRIGGER injected_failure AFTER INSERT ON members DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_write()", "DROP TRIGGER injected_failure ON members"),
    ];
    for (inject, restore) in stages {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space = Uuid::new_v4();
        create_space(&storage, space).await;
        let entry = member_entry(&[], &[1; 32], b"membership");
        sqlx::query("CREATE FUNCTION fail_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected persistence failure'; END $$")
            .execute(storage.pool()).await.expect("failure function");
        sqlx::query(inject)
            .execute(storage.pool())
            .await
            .expect("inject");
        database_error(storage.append_member(space, 0, &entry).await);
        if inject.contains("unavailable_seq") {
            database_error(storage.get_members(space, 0).await);
        }
        sqlx::query(restore)
            .execute(storage.pool())
            .await
            .expect("restore");
        let before = storage.get_space(space).await.expect("space");
        assert_eq!(before.cursor, 0, "{inject}");
        assert_eq!(before.metadata_version, 0, "{inject}");
        assert!(storage.get_members(space, 0).await.expect("log").is_empty());
        let retry = storage
            .append_member(space, 0, &entry)
            .await
            .expect("retry");
        assert_eq!(
            (retry.chain_seq, retry.cursor, retry.metadata_version),
            (1, 1, 1)
        );
        let members = storage.get_members(space, 0).await.expect("membership");
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].entry_hash, entry.entry_hash);
        storage.close().await;
    }
}

#[tokio::test]
async fn primary_signing_key_failures_preserve_the_previous_primary() {
    let stages = [
        "CREATE TRIGGER injected_failure BEFORE UPDATE ON federation_signing_keys FOR EACH ROW WHEN (OLD.is_primary AND NOT NEW.is_primary) EXECUTE FUNCTION fail_write()",
        "CREATE TRIGGER injected_failure BEFORE UPDATE ON federation_signing_keys FOR EACH ROW WHEN (NEW.kid = 'new' AND NEW.is_primary) EXECUTE FUNCTION fail_write()",
        "CREATE CONSTRAINT TRIGGER injected_failure AFTER UPDATE ON federation_signing_keys DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_write()",
    ];
    for inject in stages {
        let Some(storage) = test_storage().await else {
            return;
        };
        storage
            .ensure_federation_key("old", &[1; 32], &[2; 32])
            .await
            .expect("old key");
        storage
            .ensure_federation_key("new", &[3; 32], &[4; 32])
            .await
            .expect("new key");
        sqlx::query("CREATE FUNCTION fail_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected persistence failure'; END $$")
            .execute(storage.pool()).await.expect("failure function");
        sqlx::query(inject)
            .execute(storage.pool())
            .await
            .expect("inject");
        database_error(storage.set_federation_primary_key("new").await);
        sqlx::query("DROP TRIGGER injected_failure ON federation_signing_keys")
            .execute(storage.pool())
            .await
            .expect("restore");
        assert_eq!(
            storage
                .get_federation_signing_key()
                .await
                .expect("signing key")
                .expect("primary retained")
                .kid,
            "old"
        );
        assert_eq!(
            storage
                .list_federation_public_keys()
                .await
                .expect("public keys")
                .len(),
            2
        );
        storage
            .set_federation_primary_key("new")
            .await
            .expect("retry");
        assert_eq!(
            storage
                .get_federation_signing_key()
                .await
                .expect("signing key")
                .expect("new primary")
                .kid,
            "new"
        );
        storage.close().await;
    }
}
