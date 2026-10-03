//! Real WebSocket RPC -> SyncStorage adapter -> PostgreSQL integration tests.
use super::*;
use betterbase_sync_core::protocol::*;
use betterbase_sync_storage::postgres::PostgresStorage;
use betterbase_sync_storage::{FileStorage, SpaceStorage};
use sqlx::postgres::PgPoolOptions;

pub(super) struct TestDatabase {
    pub(super) storage: Arc<PostgresStorage>,
    schema: String,
}

impl TestDatabase {
    pub(super) async fn new() -> Option<Self> {
        let url = match std::env::var("DATABASE_URL") {
            Ok(url) => url,
            Err(_) => {
                assert_ne!(
                    std::env::var("BB_TEST_REQUIRE_DB").ok().as_deref(),
                    Some("1"),
                    "BB_TEST_REQUIRE_DB=1 but DATABASE_URL is not set"
                );
                return None;
            }
        };
        let schema = format!("test_{}", Uuid::new_v4().simple());
        let opts: sqlx::postgres::PgConnectOptions = url.parse().expect("DATABASE_URL");
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(opts.options([("search_path", schema.as_str())]))
            .await
            .expect("connect database");
        sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
            .execute(&pool)
            .await
            .expect("schema");
        betterbase_sync_storage::migrate_with_pool(&pool)
            .await
            .expect("migrations");
        Some(Self {
            storage: Arc::new(PostgresStorage::from_pool(pool)),
            schema,
        })
    }

    pub(super) async fn close(self) {
        sqlx::query(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema))
            .execute(self.storage.pool())
            .await
            .expect("remove schema");
        self.storage.as_ref().clone().close().await;
    }
}

async fn connect(server: &TestServer, token: &str) -> TestSocket {
    let (mut socket, _) = connect_async(ws_request(
        server.addr,
        Some(betterbase_sync_realtime::ws::WS_SUBPROTOCOL),
    ))
    .await
    .expect("connect");
    send_auth_with_token(&mut socket, token).await;
    socket
}

async fn call<P: serde::Serialize, R: for<'de> Deserialize<'de>>(
    socket: &mut TestSocket,
    method: &str,
    params: &P,
) -> R {
    send_rpc_request(socket, method, method, params).await;
    let frame = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .expect("response deadline")
        .expect("response")
        .expect("read");
    let WsMessage::Binary(bytes) = frame else {
        panic!("expected binary response for {method}");
    };
    let response: RpcResultResponse<R> =
        minicbor_serde::from_slice(&bytes).unwrap_or_else(|error| {
            panic!(
                "unexpected response for {method}: {error}; {:?}",
                minicbor_serde::from_slice::<CborValue>(&bytes)
            );
        });
    assert_eq!(response.id, method);
    response.result
}

fn wrapper(epoch: i32, fill: u8) -> Vec<u8> {
    let mut result = vec![fill; 44];
    result[..4].copy_from_slice(&epoch.to_be_bytes());
    result
}

#[tokio::test]
async fn postgres_websocket_push_membership_file_and_incremental_pull() {
    let Some(db) = TestDatabase::new().await else {
        return;
    };
    let server = spawn_server(
        base_state_with_ws(Duration::from_secs(1), "sync").with_sync_storage(db.storage.clone()),
    )
    .await;
    let mut socket = connect(&server, "valid-token").await;
    let space = test_personal_space_id();
    let subscribed: SubscribeResult = call(
        &mut socket,
        "subscribe",
        &serde_json::json!({"spaces": [{"id": space, "since": 0}]}),
    )
    .await;
    assert_eq!(subscribed.spaces.len(), 1);
    assert_eq!(subscribed.spaces[0].cursor, 0);
    let record_id = Uuid::new_v4();
    let push = PushParams {
        space: space.clone(),
        ucan: String::new(),
        epoch: 1,
        changes: vec![WsPushChange {
            id: record_id.to_string(),
            blob: Some(vec![0, 128, 255]),
            expected_cursor: 0,
            wrapped_dek: Some(wrapper(1, 7)),
        }],
    };
    let pushed: PushRpcResult = call(&mut socket, "push", &push).await;
    assert!(pushed.ok);
    assert_eq!(pushed.cursor, 1);
    let payload = b"opaque member".to_vec();
    let append = MembershipAppendParams {
        space: space.clone(),
        ucan: String::new(),
        expected_version: 0,
        prev_hash: None,
        entry_hash: Sha256::digest(&payload).to_vec(),
        payload: payload.clone(),
        kind: None,
    };
    let member: MembershipAppendResult = call(&mut socket, "membership.append", &append).await;
    assert_eq!((member.chain_seq, member.metadata_version), (1, 1));
    let listed: MembershipListResult = call(
        &mut socket,
        "membership.list",
        &MembershipListParams {
            space: space.clone(),
            ucan: String::new(),
            since_seq: 0,
        },
    )
    .await;
    assert_eq!(listed.metadata_version, 1);
    assert_eq!(listed.entries.len(), 1);
    assert_eq!(listed.entries[0].entry_hash, append.entry_hash);
    // Version conflicts must leave the unified cursor unchanged.
    send_rpc_request(&mut socket, "stale", "membership.append", &append).await;
    assert_eq!(
        read_error_response(&mut socket).await.error.code,
        ERR_CODE_CONFLICT
    );
    let file_id = Uuid::new_v4();
    FileStorage::record_file(
        db.storage.as_ref(),
        test_personal_space_uuid(),
        file_id,
        record_id,
        17,
        &wrapper(1, 8),
    )
    .await
    .expect("file metadata");
    send_rpc_request(
        &mut socket,
        "pull",
        "pull",
        &serde_json::json!({"spaces": [{"id": space, "since": 0}]}),
    )
    .await;
    let begin: RpcChunkResponse<WsPullBeginData> = read_chunk_response(&mut socket).await;
    assert_eq!(begin.name, "pull.begin");
    assert_eq!(begin.data.cursor, 3);
    let record: RpcChunkResponse<WsPullRecordData> = read_chunk_response(&mut socket).await;
    assert_eq!(record.name, "pull.record");
    assert_eq!(record.data.blob, Some(vec![0, 128, 255]));
    assert_eq!(record.data.wrapped_dek, Some(wrapper(1, 7)));
    let membership: RpcChunkResponse<WsMembershipData> = read_chunk_response(&mut socket).await;
    assert_eq!(membership.name, "pull.membership");
    assert_eq!(membership.data.cursor, 2);
    assert_eq!(membership.data.entries[0].payload, payload);
    assert_eq!(membership.data.entries[0].prev_hash, None);
    let file: RpcChunkResponse<WsPullFileData> = read_chunk_response(&mut socket).await;
    assert_eq!(file.name, "pull.file");
    assert_eq!(file.data.id, file_id.to_string());
    assert_eq!(file.data.record_id, record_id.to_string());
    assert_eq!(file.data.size, 17);
    assert_eq!(file.data.wrapped_dek, Some(wrapper(1, 8)));
    let commit: RpcChunkResponse<WsPullCommitData> = read_chunk_response(&mut socket).await;
    assert_eq!(commit.name, "pull.commit");
    assert_eq!((commit.data.cursor, commit.data.count), (3, 3));
    let result: RpcResultResponse<PullSummaryResult> = read_result_response(&mut socket).await;
    assert_eq!(result.result.chunks, 5);
    let mut tombstone = push;
    tombstone.changes[0].blob = None;
    tombstone.changes[0].wrapped_dek = None;
    tombstone.changes[0].expected_cursor = 1;
    let deleted: PushRpcResult = call(&mut socket, "push", &tombstone).await;
    assert!(deleted.ok);
    assert_eq!(deleted.cursor, 4);
    send_rpc_request(
        &mut socket,
        "delta",
        "pull",
        &serde_json::json!({"spaces": [{"id": space, "since": 3}]}),
    )
    .await;
    let _: RpcChunkResponse<WsPullBeginData> = read_chunk_response(&mut socket).await;
    let tombstone: RpcChunkResponse<WsPullRecordData> = read_chunk_response(&mut socket).await;
    assert!(tombstone.data.deleted);
    assert_eq!(tombstone.data.blob, None);
    let _: RpcChunkResponse<WsPullCommitData> = read_chunk_response(&mut socket).await;
    let _: RpcResultResponse<PullSummaryResult> = read_result_response(&mut socket).await;
    server.handle.abort();
    drop(socket);
    db.close().await;
}

#[tokio::test]
async fn postgres_websocket_epoch_shares_are_member_scoped_and_rotation_prunes_old_keys() {
    let Some(db) = TestDatabase::new().await else {
        return;
    };
    let space_id = Uuid::new_v4();
    let root = TestIssuer::new();
    let admin = TestIssuer::new();
    let member = TestIssuer::new();
    let other = TestIssuer::new();
    let admin_ucan = root.issue_space_ucan(&admin.did, space_id, Permission::Admin);
    let member_ucan = root.issue_space_ucan(&member.did, space_id, Permission::Read);
    let other_ucan = root.issue_space_ucan(&other.did, space_id, Permission::Read);
    let tokens = HashMap::from([
        (
            "admin".into(),
            test_auth_context_with_did("sync files", &admin.did),
        ),
        (
            "member".into(),
            test_auth_context_with_did("sync", &member.did),
        ),
        (
            "other".into(),
            test_auth_context_with_did("sync", &other.did),
        ),
    ]);
    SpaceStorage::create_space(
        db.storage.as_ref(),
        space_id,
        "client-1",
        Some(&root.compressed_public_key()),
    )
    .await
    .expect("shared space");
    let server = spawn_server(
        base_state_with_ws_validator(Duration::from_secs(1), Arc::new(StubValidator { tokens }))
            .with_sync_storage(db.storage.clone()),
    )
    .await;
    let mut admin_socket = connect(&server, "admin").await;
    let mut member_socket = connect(&server, "member").await;
    let mut other_socket = connect(&server, "other").await;
    let space = space_id.to_string();
    let put = EpochKeysPutParams {
        space: space.clone(),
        ucan: admin_ucan.clone(),
        epoch: 1,
        keys: vec![EpochKeyShareEntry {
            member_did: member.did.clone(),
            wrapped_key: vec![1, 128, 255],
        }],
    };
    let result: EpochKeysPutResult = call(&mut admin_socket, "epochKeys.put", &put).await;
    assert_eq!(result.count, 1);
    let get = EpochKeysGetParams {
        space: space.clone(),
        ucan: member_ucan,
        epoch: 1,
    };
    let own: EpochKeysGetResult = call(&mut member_socket, "epochKeys.get", &get).await;
    assert_eq!(own.wrapped_key, vec![1, 128, 255]);
    send_rpc_request(
        &mut other_socket,
        "other",
        "epochKeys.get",
        &EpochKeysGetParams {
            ucan: other_ucan,
            ..get.clone()
        },
    )
    .await;
    assert_eq!(
        read_error_response(&mut other_socket).await.error.code,
        ERR_CODE_NOT_FOUND
    );
    let begun: EpochBeginResult = call(
        &mut admin_socket,
        "epoch.begin",
        &EpochBeginParams {
            space: space.clone(),
            ucan: admin_ucan.clone(),
            epoch: 2,
            set_min_epoch: true,
        },
    )
    .await;
    assert_eq!(begun.epoch, 2);
    let next = EpochKeysPutParams { epoch: 2, ..put };
    let _: EpochKeysPutResult = call(&mut admin_socket, "epochKeys.put", &next).await;
    let _: serde_json::Value = call(
        &mut admin_socket,
        "epoch.complete",
        &EpochCompleteParams {
            space: space.clone(),
            ucan: admin_ucan.clone(),
            epoch: 2,
        },
    )
    .await;
    // Keep the immediately preceding epoch for devices still catching up.
    let retained: EpochKeysGetResult = call(&mut member_socket, "epochKeys.get", &get).await;
    assert_eq!(retained.wrapped_key, vec![1, 128, 255]);
    let _: EpochBeginResult = call(
        &mut admin_socket,
        "epoch.begin",
        &EpochBeginParams {
            space: space.clone(),
            ucan: admin_ucan.clone(),
            epoch: 3,
            set_min_epoch: true,
        },
    )
    .await;
    let _: EpochKeysPutResult = call(
        &mut admin_socket,
        "epochKeys.put",
        &EpochKeysPutParams { epoch: 3, ..next },
    )
    .await;
    let _: serde_json::Value = call(
        &mut admin_socket,
        "epoch.complete",
        &EpochCompleteParams {
            space,
            ucan: admin_ucan,
            epoch: 3,
        },
    )
    .await;
    send_rpc_request(&mut member_socket, "old", "epochKeys.get", &get).await;
    assert_eq!(
        read_error_response(&mut member_socket).await.error.code,
        ERR_CODE_NOT_FOUND
    );
    let new: EpochKeysGetResult = call(
        &mut member_socket,
        "epochKeys.get",
        &EpochKeysGetParams { epoch: 2, ..get },
    )
    .await;
    assert_eq!(new.wrapped_key, vec![1, 128, 255]);
    server.handle.abort();
    drop((admin_socket, member_socket, other_socket));
    db.close().await;
}

#[tokio::test]
async fn postgres_websocket_invitation_crud_and_rate_limit() {
    let Some(db) = TestDatabase::new().await else {
        return;
    };
    let mut other_auth = test_auth_context("sync");
    other_auth.mailbox_id = TEST_OTHER_MAILBOX_ID.into();
    other_auth.user_id = "user-2".into();
    let tokens = HashMap::from([
        ("valid-token".into(), test_auth_context("sync")),
        ("other-token".into(), other_auth),
    ]);
    let server = spawn_server(
        base_state_with_ws_validator(Duration::from_secs(1), Arc::new(StubValidator { tokens }))
            .with_sync_storage(db.storage.clone())
            .with_identity_hash_key(vec![42; 32]),
    )
    .await;
    let mut socket = connect(&server, "valid-token").await;
    let invitation = InvitationCreateParams {
        mailbox_id: TEST_MAILBOX_ID.into(),
        payload: "encrypted invitation".into(),
        server: String::new(),
    };
    let created: InvitationCreateResult = call(&mut socket, "invitation.create", &invitation).await;
    let mut other_socket = connect(&server, "other-token").await;
    let other_list: InvitationListResult = call(
        &mut other_socket,
        "invitation.list",
        &InvitationListParams {
            limit: 10,
            after: String::new(),
        },
    )
    .await;
    assert!(other_list.invitations.is_empty());
    send_rpc_request(
        &mut other_socket,
        "other-get",
        "invitation.get",
        &InvitationGetParams {
            id: created.id.clone(),
        },
    )
    .await;
    assert_eq!(
        read_error_response(&mut other_socket).await.error.code,
        ERR_CODE_NOT_FOUND
    );
    send_rpc_request(
        &mut other_socket,
        "other-delete",
        "invitation.delete",
        &InvitationDeleteParams {
            id: created.id.clone(),
        },
    )
    .await;
    assert_eq!(
        read_error_response(&mut other_socket).await.error.code,
        ERR_CODE_NOT_FOUND
    );
    let got: InvitationCreateResult = call(
        &mut socket,
        "invitation.get",
        &InvitationGetParams {
            id: created.id.clone(),
        },
    )
    .await;
    assert_eq!(got.payload, invitation.payload);
    let listed: InvitationListResult = call(
        &mut socket,
        "invitation.list",
        &InvitationListParams {
            limit: 10,
            after: String::new(),
        },
    )
    .await;
    assert_eq!(listed.invitations.len(), 1);
    assert_eq!(listed.invitations[0].id, created.id);
    let _: serde_json::Value = call(
        &mut socket,
        "invitation.delete",
        &InvitationDeleteParams {
            id: created.id.clone(),
        },
    )
    .await;
    send_rpc_request(
        &mut socket,
        "missing",
        "invitation.get",
        &InvitationGetParams { id: created.id },
    )
    .await;
    assert_eq!(
        read_error_response(&mut socket).await.error.code,
        ERR_CODE_NOT_FOUND
    );
    for _ in 1..10 {
        let _: InvitationCreateResult = call(&mut socket, "invitation.create", &invitation).await;
    }
    send_rpc_request(&mut socket, "limited", "invitation.create", &invitation).await;
    assert_eq!(
        read_error_response(&mut socket).await.error.code,
        ERR_CODE_RATE_LIMITED
    );
    let listed: InvitationListResult = call(
        &mut socket,
        "invitation.list",
        &InvitationListParams {
            limit: 100,
            after: String::new(),
        },
    )
    .await;
    assert_eq!(listed.invitations.len(), 9);
    server.handle.abort();
    drop((socket, other_socket));
    db.close().await;
}

#[tokio::test]
async fn postgres_websocket_rewrap_compare_and_set_and_ucan_revocation() {
    let Some(db) = TestDatabase::new().await else {
        return;
    };
    let space_id = Uuid::new_v4();
    let space = space_id.to_string();
    let root = TestIssuer::new();
    let admin = TestIssuer::new();
    let reader = TestIssuer::new();
    let admin_ucan = root.issue_space_ucan(&admin.did, space_id, Permission::Admin);
    let reader_ucan = root.issue_space_ucan(&reader.did, space_id, Permission::Read);
    let tokens = HashMap::from([
        (
            "admin".into(),
            test_auth_context_with_did("sync files", &admin.did),
        ),
        (
            "reader".into(),
            test_auth_context_with_did("sync", &reader.did),
        ),
    ]);
    let server = spawn_server(
        base_state_with_ws_validator(Duration::from_secs(1), Arc::new(StubValidator { tokens }))
            .with_sync_storage(db.storage.clone()),
    )
    .await;
    let mut socket = connect(&server, "admin").await;
    let mut reader_socket = connect(&server, "reader").await;
    let created: SpaceCreateResult = call(
        &mut socket,
        "space.create",
        &SpaceCreateParams {
            id: space.clone(),
            root_public_key: root.compressed_public_key().to_vec(),
        },
    )
    .await;
    assert_eq!(created.epoch, 1);
    let record_id = Uuid::new_v4();
    let pushed: PushRpcResult = call(
        &mut socket,
        "push",
        &PushParams {
            space: space.clone(),
            ucan: admin_ucan.clone(),
            epoch: 1,
            changes: vec![WsPushChange {
                id: record_id.to_string(),
                blob: Some(vec![1, 2, 3]),
                expected_cursor: 0,
                wrapped_dek: Some(wrapper(1, 7)),
            }],
        },
    )
    .await;
    assert!(pushed.ok);
    let file_id = Uuid::new_v4();
    FileStorage::record_file(
        db.storage.as_ref(),
        space_id,
        file_id,
        record_id,
        3,
        &wrapper(1, 8),
    )
    .await
    .expect("file");
    let old: DeksGetResult = call(
        &mut reader_socket,
        "deks.get",
        &DeksGetParams {
            space: space.clone(),
            ucan: reader_ucan.clone(),
            since: 0,
        },
    )
    .await;
    assert_eq!(old.deks[0].wrapped_dek, wrapper(1, 7));
    let _: EpochBeginResult = call(
        &mut socket,
        "epoch.begin",
        &EpochBeginParams {
            space: space.clone(),
            ucan: admin_ucan.clone(),
            epoch: 2,
            set_min_epoch: true,
        },
    )
    .await;
    let rewrap = DeksRewrapParams {
        space: space.clone(),
        ucan: admin_ucan.clone(),
        deks: vec![DekRewrapEntry {
            id: record_id.to_string(),
            wrapped_dek: wrapper(2, 9),
            observed_wrapped_dek: Some(wrapper(1, 7)),
        }],
    };
    let updated: DeksRewrapResult = call(&mut socket, "deks.rewrap", &rewrap).await;
    assert!(updated.ok);
    assert_eq!(updated.count, 1);
    send_rpc_request(&mut socket, "stale", "deks.rewrap", &rewrap).await;
    assert_eq!(
        read_error_response(&mut socket).await.error.code,
        ERR_CODE_CONFLICT
    );
    let files: FileDeksGetResult = call(
        &mut socket,
        "file.deks.get",
        &FileDeksGetParams {
            space: space.clone(),
            ucan: admin_ucan.clone(),
            since: 0,
        },
    )
    .await;
    assert_eq!(files.deks[0].wrapped_dek, wrapper(1, 8));
    let rewrap = FileDeksRewrapParams {
        space: space.clone(),
        ucan: admin_ucan.clone(),
        deks: vec![FileDekRewrapEntry {
            id: file_id.to_string(),
            wrapped_dek: wrapper(2, 10),
            observed_wrapped_dek: Some(wrapper(1, 8)),
        }],
    };
    let files: FileDeksRewrapResult = call(&mut socket, "file.deks.rewrap", &rewrap).await;
    assert!(files.ok);
    send_rpc_request(&mut socket, "stale-file", "file.deks.rewrap", &rewrap).await;
    assert_eq!(
        read_error_response(&mut socket).await.error.code,
        ERR_CODE_CONFLICT
    );
    let files: FileDeksGetResult = call(
        &mut socket,
        "file.deks.get",
        &FileDeksGetParams {
            space: space.clone(),
            ucan: admin_ucan.clone(),
            since: 0,
        },
    )
    .await;
    assert_eq!(files.deks[0].wrapped_dek, wrapper(2, 10));
    let records: DeksGetResult = call(
        &mut socket,
        "deks.get",
        &DeksGetParams {
            space: space.clone(),
            ucan: admin_ucan.clone(),
            since: 0,
        },
    )
    .await;
    assert_eq!(records.deks[0].wrapped_dek, wrapper(2, 9));
    let _: serde_json::Value = call(
        &mut socket,
        "membership.revoke",
        &MembershipRevokeParams {
            space: space.clone(),
            ucan: admin_ucan,
            ucan_cid: compute_ucan_cid(&reader_ucan),
            member_did: reader.did,
        },
    )
    .await;
    send_rpc_request(
        &mut reader_socket,
        "revoked",
        "deks.get",
        &DeksGetParams {
            space,
            ucan: reader_ucan,
            since: 0,
        },
    )
    .await;
    assert_eq!(
        read_error_response(&mut reader_socket).await.error.code,
        ERR_CODE_FORBIDDEN
    );
    server.handle.abort();
    drop((socket, reader_socket));
    db.close().await;
}
