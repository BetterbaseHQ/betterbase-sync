//! Wire-level validation and failure paths that ordinary success tests miss.
use super::*;
use betterbase_sync_core::protocol::*;
use betterbase_sync_storage::StorageError;

async fn connect(server: &TestServer) -> TestSocket {
    let (mut socket, _) = connect_async(ws_request(
        server.addr,
        Some(betterbase_sync_realtime::ws::WS_SUBPROTOCOL),
    ))
    .await
    .expect("connect");
    send_auth(&mut socket).await;
    socket
}

fn put_params() -> EpochKeysPutParams {
    EpochKeysPutParams {
        space: test_personal_space_id(),
        ucan: String::new(),
        epoch: 2,
        keys: vec![EpochKeyShareEntry {
            member_did: "did:key:member".into(),
            wrapped_key: vec![7],
        }],
    }
}

fn member_params() -> MembershipAppendParams {
    let payload = b"encrypted membership".to_vec();
    MembershipAppendParams {
        space: test_personal_space_id(),
        ucan: String::new(),
        expected_version: 0,
        prev_hash: None,
        entry_hash: Sha256::digest(&payload).to_vec(),
        payload,
        kind: None,
    }
}

#[tokio::test]
async fn epoch_keys_reject_malformed_params_and_space_ids() {
    let server = spawn_server(base_state_with_ws_and_storage(
        Duration::from_secs(1),
        "sync",
        Arc::new(StubSyncStorage::healthy()),
    ))
    .await;
    let mut socket = connect(&server).await;
    for method in ["epochKeys.put", "epochKeys.get"] {
        send_rpc_request(&mut socket, "malformed", method, &serde_json::json!({})).await;
        assert_eq!(
            read_error_response(&mut socket).await.error.code,
            ERR_CODE_INVALID_PARAMS
        );
        send_rpc_request(
            &mut socket,
            "uuid",
            method,
            &serde_json::json!({"space": "bad", "epoch": 2, "keys": []}),
        )
        .await;
        assert_eq!(
            read_error_response(&mut socket).await.error.code,
            ERR_CODE_BAD_REQUEST
        );
    }
    server.handle.abort();
}

#[tokio::test]
async fn epoch_keys_put_checks_share_count_and_blob_boundaries_before_storage() {
    let storage = Arc::new(StubSyncStorage::healthy());
    let server = spawn_server(base_state_with_ws_and_storage(
        Duration::from_secs(1),
        "sync",
        storage.clone(),
    ))
    .await;
    let mut socket = connect(&server).await;
    for keys in [
        vec![],
        vec![put_params().keys[0].clone(); 1001],
        vec![EpochKeyShareEntry {
            member_did: String::new(),
            wrapped_key: vec![1],
        }],
        vec![EpochKeyShareEntry {
            member_did: "member".into(),
            wrapped_key: vec![],
        }],
        vec![EpochKeyShareEntry {
            member_did: "member".into(),
            wrapped_key: vec![1; 2049],
        }],
    ] {
        let mut params = put_params();
        params.keys = keys;
        send_rpc_request(&mut socket, "invalid", "epochKeys.put", &params).await;
        assert_eq!(
            read_error_response(&mut socket).await.error.code,
            ERR_CODE_BAD_REQUEST
        );
        assert!(storage.stored_key_shares.lock().await.is_empty());
    }
    let mut params = put_params();
    params.keys = (0..1000)
        .map(|n| EpochKeyShareEntry {
            member_did: format!("member-{n}"),
            wrapped_key: vec![42; 2048],
        })
        .collect();
    send_rpc_request(&mut socket, "boundary", "epochKeys.put", &params).await;
    let response: RpcResultResponse<EpochKeysPutResult> = read_result_response(&mut socket).await;
    assert_eq!(response.result.count, 1000);
    let stored = storage.stored_key_shares.lock().await;
    assert_eq!(stored.len(), 1000);
    assert_eq!(stored[999].member_did, "member-999");
    assert_eq!(stored[999].wrapped_key, vec![42; 2048]);
    server.handle.abort();
}

#[tokio::test]
async fn epoch_keys_put_maps_storage_failures() {
    for (error, code) in [
        (StorageError::SpaceNotFound, ERR_CODE_NOT_FOUND),
        (StorageError::Unavailable, ERR_CODE_INTERNAL),
    ] {
        let storage = Arc::new(StubSyncStorage {
            epoch_keys_put_error: Some(error),
            ..StubSyncStorage::healthy()
        });
        let server = spawn_server(base_state_with_ws_and_storage(
            Duration::from_secs(1),
            "sync",
            storage.clone(),
        ))
        .await;
        let mut socket = connect(&server).await;
        send_rpc_request(&mut socket, "put", "epochKeys.put", &put_params()).await;
        assert_eq!(read_error_response(&mut socket).await.error.code, code);
        assert!(storage.stored_key_shares.lock().await.is_empty());
        server.handle.abort();
    }
}

#[tokio::test]
async fn epoch_keys_get_uses_authenticated_did_and_preserves_binary_key() {
    let storage = Arc::new(StubSyncStorage {
        epoch_keys_get_result: Ok(vec![0, 128, 255]),
        ..StubSyncStorage::healthy()
    });
    let server = spawn_server(base_state_with_ws_and_storage(
        Duration::from_secs(1),
        "sync",
        storage.clone(),
    ))
    .await;
    let mut socket = connect(&server).await;
    // An extra wire field cannot redirect the lookup to another member.
    send_rpc_request(&mut socket, "get", "epochKeys.get", &serde_json::json!({"space": test_personal_space_id(), "epoch": 2, "member_did": "someone-else"})).await;
    let response: RpcResultResponse<EpochKeysGetResult> = read_result_response(&mut socket).await;
    assert_eq!(response.result.wrapped_key, vec![0, 128, 255]);
    assert_eq!(
        *storage.requested_key_dids.lock().await,
        vec![test_auth_context("sync").did]
    );
    server.handle.abort();
}

#[tokio::test]
async fn epoch_keys_get_maps_missing_share_space_and_database_failure() {
    for (error, code) in [
        (StorageError::EpochKeyShareNotFound, ERR_CODE_NOT_FOUND),
        (StorageError::SpaceNotFound, ERR_CODE_NOT_FOUND),
        (StorageError::Unavailable, ERR_CODE_INTERNAL),
    ] {
        let server = spawn_server(base_state_with_ws_and_storage(
            Duration::from_secs(1),
            "sync",
            Arc::new(StubSyncStorage {
                epoch_keys_get_result: Err(error),
                ..StubSyncStorage::healthy()
            }),
        ))
        .await;
        let mut socket = connect(&server).await;
        send_rpc_request(
            &mut socket,
            "get",
            "epochKeys.get",
            &EpochKeysGetParams {
                space: test_personal_space_id(),
                ucan: String::new(),
                epoch: 2,
            },
        )
        .await;
        assert_eq!(read_error_response(&mut socket).await.error.code, code);
        server.handle.abort();
    }
}

#[tokio::test]
async fn epoch_keys_authorization_failures_never_access_shares() {
    for internal in [false, true] {
        let mut storage = StubSyncStorage::healthy();
        if internal {
            storage.fail_for.insert(test_personal_space_uuid());
        }
        let storage = Arc::new(storage);
        let server = spawn_server(base_state_with_ws_and_storage(
            Duration::from_secs(1),
            "sync",
            storage.clone(),
        ))
        .await;
        let mut socket = connect(&server).await;
        let space = if internal {
            test_personal_space_id()
        } else {
            Uuid::new_v4().to_string()
        };
        let mut put = put_params();
        put.space = space.clone();
        send_rpc_request(&mut socket, "put", "epochKeys.put", &put).await;
        let code = if internal {
            ERR_CODE_INTERNAL
        } else {
            ERR_CODE_FORBIDDEN
        };
        assert_eq!(read_error_response(&mut socket).await.error.code, code);
        send_rpc_request(
            &mut socket,
            "get",
            "epochKeys.get",
            &EpochKeysGetParams {
                space,
                ucan: String::new(),
                epoch: 2,
            },
        )
        .await;
        assert_eq!(read_error_response(&mut socket).await.error.code, code);
        assert!(storage.stored_key_shares.lock().await.is_empty());
        assert!(storage.requested_key_dids.lock().await.is_empty());
        server.handle.abort();
    }
}

#[tokio::test]
async fn membership_append_rejects_invalid_hashes_and_empty_payloads() {
    let storage = Arc::new(StubSyncStorage::healthy());
    let server = spawn_server(
        base_state_with_ws_and_storage(Duration::from_secs(1), "sync", storage.clone())
            .with_identity_hash_key(vec![9; 32]),
    )
    .await;
    let mut socket = connect(&server).await;
    for (hash, payload) in [
        (vec![0; 31], vec![1]),
        (vec![0; 33], vec![1]),
        (vec![0; 32], vec![]),
        (vec![0; 32], vec![1]),
    ] {
        let mut params = member_params();
        params.entry_hash = hash;
        params.payload = payload;
        send_rpc_request(&mut socket, "invalid", "membership.append", &params).await;
        assert_eq!(
            read_error_response(&mut socket).await.error.code,
            ERR_CODE_BAD_REQUEST
        );
        assert!(storage.recorded_actions.lock().await.is_empty());
    }
    server.handle.abort();
}

#[tokio::test]
async fn membership_append_maps_storage_errors_without_recording_actions() {
    for (error, code) in [
        (StorageError::SpaceNotFound, ERR_CODE_NOT_FOUND),
        (StorageError::HashChainBroken, ERR_CODE_CONFLICT),
        (StorageError::Unavailable, ERR_CODE_INTERNAL),
    ] {
        let storage = Arc::new(StubSyncStorage {
            append_error: Some(error),
            ..StubSyncStorage::healthy()
        });
        let server = spawn_server(
            base_state_with_ws_and_storage(Duration::from_secs(1), "sync", storage.clone())
                .with_identity_hash_key(vec![9; 32]),
        )
        .await;
        let mut socket = connect(&server).await;
        send_rpc_request(&mut socket, "append", "membership.append", &member_params()).await;
        assert_eq!(read_error_response(&mut socket).await.error.code, code);
        assert!(storage.recorded_actions.lock().await.is_empty());
        server.handle.abort();
    }
}

async fn send_limited_request(socket: &mut TestSocket, method: &str) {
    if method == "membership.append" {
        send_rpc_request(socket, "limited", method, &member_params()).await;
    } else {
        send_rpc_request(
            socket,
            "limited",
            method,
            &InvitationCreateParams {
                mailbox_id: TEST_OTHER_MAILBOX_ID.into(),
                payload: "opaque".into(),
                server: String::new(),
            },
        )
        .await;
    }
}

#[tokio::test]
async fn membership_and_invitation_limits_fail_closed() {
    for (method, limit) in [("membership.append", 30), ("invitation.create", 10)] {
        for (usage, code) in [
            (Ok(limit), ERR_CODE_RATE_LIMITED),
            (Ok(limit + 1), ERR_CODE_RATE_LIMITED),
            (Err(StorageError::Unavailable), ERR_CODE_INTERNAL),
        ] {
            let storage = Arc::new(StubSyncStorage {
                recent_actions: usage,
                ..StubSyncStorage::healthy()
            });
            let server = spawn_server(
                base_state_with_ws_and_storage(Duration::from_secs(1), "sync", storage.clone())
                    .with_identity_hash_key(vec![9; 32]),
            )
            .await;
            let mut socket = connect(&server).await;
            send_limited_request(&mut socket, method).await;
            assert_eq!(read_error_response(&mut socket).await.error.code, code);
            assert!(storage.recorded_actions.lock().await.is_empty());
            server.handle.abort();
        }
    }
}

#[tokio::test]
async fn successful_limited_actions_record_private_actor_hash() {
    let key = vec![9; 32];
    let auth = test_auth_context("sync");
    let hash = betterbase_sync_storage::rate_limit_hash(&key, &auth.issuer, &auth.user_id);
    for (method, limit, action) in [
        ("membership.append", 30, "membership_append"),
        ("invitation.create", 10, "invitation"),
    ] {
        let storage = Arc::new(StubSyncStorage {
            recent_actions: Ok(limit - 1),
            ..StubSyncStorage::healthy()
        });
        let server = spawn_server(
            base_state_with_ws_and_storage(Duration::from_secs(1), "sync", storage.clone())
                .with_identity_hash_key(key.clone()),
        )
        .await;
        let mut socket = connect(&server).await;
        send_limited_request(&mut socket, method).await;
        let _: RpcResultResponse<serde_json::Value> = read_result_response(&mut socket).await;
        assert_eq!(
            *storage.recorded_actions.lock().await,
            vec![(action.into(), hash.clone())]
        );
        server.handle.abort();
    }
}

#[tokio::test]
async fn accounting_failure_after_commit_does_not_report_failed_write() {
    for method in ["membership.append", "invitation.create"] {
        let storage = Arc::new(StubSyncStorage {
            record_action_error: Some(StorageError::Unavailable),
            ..StubSyncStorage::healthy()
        });
        let server = spawn_server(
            base_state_with_ws_and_storage(Duration::from_secs(1), "sync", storage)
                .with_identity_hash_key(vec![9; 32]),
        )
        .await;
        let mut socket = connect(&server).await;
        send_limited_request(&mut socket, method).await;
        let response: RpcResultResponse<serde_json::Value> =
            read_result_response(&mut socket).await;
        assert_eq!(response.id, "limited");
        server.handle.abort();
    }
}

#[tokio::test]
async fn storage_dependent_methods_fail_explicitly_when_storage_is_not_configured() {
    let server = spawn_server(base_state_with_ws(Duration::from_secs(1), "sync files")).await;
    let mut socket = connect(&server).await;
    for method in [
        "space.create",
        "membership.append",
        "membership.list",
        "membership.revoke",
        "invitation.create",
        "invitation.list",
        "invitation.get",
        "invitation.delete",
        "epoch.begin",
        "epoch.complete",
        "epochKeys.put",
        "epochKeys.get",
        "deks.get",
        "deks.rewrap",
        "file.deks.get",
        "file.deks.rewrap",
        "deks.getFiles",
        "deks.rewrapFiles",
        "subscribe",
        "push",
        "pull",
    ] {
        send_rpc_request(&mut socket, method, method, &serde_json::json!({})).await;
        let response = read_error_response(&mut socket).await;
        assert_eq!(response.id, method);
        assert_eq!(response.error.code, ERR_CODE_INTERNAL, "{method}");
        assert_eq!(
            response.error.message, "sync storage is not configured",
            "{method}"
        );
    }
    server.handle.abort();
}
