//! Critical RPC rejection paths and their storage/broadcast side effects.
use super::*;
use betterbase_sync_core::protocol::*;
use betterbase_sync_storage::StorageError;

struct Session {
    socket: TestSocket,
    server: TestServer,
    storage: Arc<StubSyncStorage>,
}
impl Session {
    async fn new(storage: StubSyncStorage, scope: &'static str) -> Self {
        let storage = Arc::new(storage);
        let server = spawn_server(base_state_with_ws_and_storage(
            Duration::from_secs(1),
            scope,
            storage.clone(),
        ))
        .await;
        let (mut socket, _) = connect_async(ws_request(
            server.addr,
            Some(betterbase_sync_realtime::ws::WS_SUBPROTOCOL),
        ))
        .await
        .expect("connect");
        send_auth(&mut socket).await;
        Self {
            socket,
            server,
            storage,
        }
    }
    async fn error<P: serde::Serialize>(&mut self, method: &str, params: &P, code: &str) {
        send_rpc_request(&mut self.socket, method, method, params).await;
        let response = read_error_response(&mut self.socket).await;
        assert_eq!(response.id, method);
        assert_eq!(response.error.code, code, "{method}");
    }
    async fn result<P: serde::Serialize, R: for<'de> Deserialize<'de>>(
        &mut self,
        method: &str,
        params: &P,
    ) -> R {
        send_rpc_request(&mut self.socket, method, method, params).await;
        read_result_response::<R>(&mut self.socket).await.result
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.server.handle.abort();
    }
}
fn request(method: &str, space: &str) -> serde_json::Value {
    match method {
        "deks.get" | "file.deks.get" => serde_json::json!({"space":space,"since":0}),
        "deks.rewrap" | "file.deks.rewrap" => serde_json::json!({"space":space,"deks":[]}),
        "epoch.begin" => serde_json::json!({"space":space,"epoch":2}),
        "epoch.complete" => serde_json::json!({"space":space,"epoch":2}),
        "membership.list" => serde_json::json!({"space":space,"since_seq":0}),
        _ => panic!("unexpected method"),
    }
}

#[tokio::test]
async fn critical_rpcs_reject_malformed_requests_and_invalid_space_ids() {
    let mut session = Session::new(StubSyncStorage::healthy(), "sync files").await;
    for method in [
        "deks.get",
        "deks.rewrap",
        "file.deks.get",
        "file.deks.rewrap",
        "epoch.begin",
        "epoch.complete",
        "membership.list",
    ] {
        session
            .error(
                method,
                &serde_json::json!({"space":4,"epoch":"wrong","deks":"wrong"}),
                ERR_CODE_INVALID_PARAMS,
            )
            .await;
        session
            .error(method, &request(method, "invalid"), ERR_CODE_BAD_REQUEST)
            .await;
    }
    assert!(session.storage.rewrapped_deks.lock().await.is_empty());
    assert!(session.storage.rewrapped_file_deks.lock().await.is_empty());
}

#[tokio::test]
async fn deks_enforce_scope_and_write_authorization_before_storage() {
    for method in ["file.deks.get", "file.deks.rewrap"] {
        let mut session = Session::new(StubSyncStorage::healthy(), "sync").await;
        session
            .error(
                method,
                &request(method, &test_personal_space_id()),
                ERR_CODE_FORBIDDEN,
            )
            .await;
        assert!(session.storage.rewrapped_deks.lock().await.is_empty());
        assert!(session.storage.rewrapped_file_deks.lock().await.is_empty());
    }
    let mut session = Session::new(StubSyncStorage::healthy(), "sync files").await;
    for method in [
        "deks.get",
        "deks.rewrap",
        "file.deks.get",
        "file.deks.rewrap",
    ] {
        session
            .error(
                method,
                &request(method, &Uuid::new_v4().to_string()),
                ERR_CODE_FORBIDDEN,
            )
            .await;
    }
}

#[tokio::test]
async fn personal_space_storage_failures_surface_as_internal_before_mutation() {
    let storage = StubSyncStorage {
        fail_for: HashSet::from([test_personal_space_uuid()]),
        ..StubSyncStorage::healthy()
    };
    let mut session = Session::new(storage, "sync files").await;
    for method in [
        "deks.get",
        "deks.rewrap",
        "file.deks.get",
        "file.deks.rewrap",
        "epoch.begin",
        "epoch.complete",
        "membership.list",
    ] {
        session
            .error(
                method,
                &request(method, &test_personal_space_id()),
                ERR_CODE_INTERNAL,
            )
            .await;
    }
    assert!(session.storage.rewrapped_deks.lock().await.is_empty());
    assert!(session.storage.rewrapped_file_deks.lock().await.is_empty());
}

#[tokio::test]
async fn dek_storage_failures_preserve_domain_error_codes() {
    for error in [StorageError::SpaceNotFound, StorageError::Unavailable] {
        let mut session = Session::new(
            StubSyncStorage {
                operation_errors: HashMap::from([
                    ("get_deks", error.clone()),
                    ("get_file_deks", error.clone()),
                ]),
                ..StubSyncStorage::healthy()
            },
            "sync files",
        )
        .await;
        for method in ["deks.get", "file.deks.get"] {
            session
                .error(
                    method,
                    &request(method, &test_personal_space_id()),
                    if error == StorageError::SpaceNotFound {
                        ERR_CODE_NOT_FOUND
                    } else {
                        ERR_CODE_INTERNAL
                    },
                )
                .await;
        }
    }
    for (error, code) in [
        (StorageError::SpaceNotFound, ERR_CODE_NOT_FOUND),
        (StorageError::DekRecordNotFound, ERR_CODE_BAD_REQUEST),
        (StorageError::DekEpochMismatch, ERR_CODE_CONFLICT),
        (StorageError::DekConflict, ERR_CODE_CONFLICT),
        (StorageError::Unavailable, ERR_CODE_INTERNAL),
    ] {
        let file_error = if error == StorageError::DekRecordNotFound {
            StorageError::FileDekNotFound
        } else {
            error.clone()
        };
        let mut session = Session::new(
            StubSyncStorage {
                deks_rewrap_error: Some(error),
                file_deks_rewrap_error: Some(file_error),
                ..StubSyncStorage::healthy()
            },
            "sync files",
        )
        .await;
        for method in ["deks.rewrap", "file.deks.rewrap"] {
            session
                .error(method, &request(method, &test_personal_space_id()), code)
                .await;
        }
    }
}

#[tokio::test]
async fn rewrap_rejects_entire_invalid_batch_before_any_storage_write() {
    let mut session = Session::new(StubSyncStorage::healthy(), "sync files").await;
    for method in ["deks.rewrap", "file.deks.rewrap"] {
        for (id, length) in [
            (String::new(), 44),
            (Uuid::new_v4().to_string(), 43),
            (Uuid::new_v4().to_string(), 45),
        ] {
            let entries = vec![
                DekRewrapEntry {
                    id: Uuid::new_v4().to_string(),
                    wrapped_dek: vec![7; 44],
                    observed_wrapped_dek: None,
                },
                DekRewrapEntry {
                    id,
                    wrapped_dek: vec![8; length],
                    observed_wrapped_dek: None,
                },
            ];
            if method == "deks.rewrap" {
                let params = DeksRewrapParams {
                    space: test_personal_space_id(),
                    ucan: String::new(),
                    deks: entries,
                };
                session.error(method, &params, ERR_CODE_BAD_REQUEST).await;
            } else {
                let params = FileDeksRewrapParams {
                    space: test_personal_space_id(),
                    ucan: String::new(),
                    deks: entries
                        .into_iter()
                        .map(|e| FileDekRewrapEntry {
                            id: e.id,
                            wrapped_dek: e.wrapped_dek,
                            observed_wrapped_dek: e.observed_wrapped_dek,
                        })
                        .collect(),
                };
                session.error(method, &params, ERR_CODE_BAD_REQUEST).await;
            }
        }
    }
    assert!(session.storage.rewrapped_deks.lock().await.is_empty());
    assert!(session.storage.rewrapped_file_deks.lock().await.is_empty());
}

#[tokio::test]
async fn rewrap_passes_observed_keys_byte_for_byte_for_compare_and_set() {
    let mut session = Session::new(StubSyncStorage::healthy(), "sync files").await;
    let id = Uuid::new_v4();
    let params = DeksRewrapParams {
        space: test_personal_space_id(),
        ucan: String::new(),
        deks: vec![DekRewrapEntry {
            id: id.to_string(),
            wrapped_dek: vec![8; 44],
            observed_wrapped_dek: Some(vec![7; 44]),
        }],
    };
    let records: DeksRewrapResult = session.result("deks.rewrap", &params).await;
    assert!(records.ok);
    assert_eq!(records.count, 1);
    let params = FileDeksRewrapParams {
        space: params.space,
        ucan: String::new(),
        deks: params
            .deks
            .into_iter()
            .map(|e| FileDekRewrapEntry {
                id: e.id,
                wrapped_dek: e.wrapped_dek,
                observed_wrapped_dek: e.observed_wrapped_dek,
            })
            .collect(),
    };
    let files: FileDeksRewrapResult = session.result("file.deks.rewrap", &params).await;
    assert!(files.ok);
    assert_eq!(files.count, 1);
    let record = session.storage.rewrapped_deks.lock().await[0].clone();
    assert_eq!(record.observed_wrapped_dek, Some(vec![7; 44]));
    assert_eq!(record.wrapped_dek, vec![8; 44]);
    let file = session.storage.rewrapped_file_deks.lock().await[0].clone();
    assert_eq!(file.id, id);
    assert_eq!(file.observed_wrapped_dek, Some(vec![7; 44]));
}

#[tokio::test]
async fn epoch_and_membership_failures_keep_protocol_error_taxonomy() {
    for error in [StorageError::SpaceNotFound, StorageError::Unavailable] {
        let mut session = Session::new(
            StubSyncStorage {
                epoch_begin_error: Some(error.clone()),
                epoch_complete_error: Some(error.clone()),
                operation_errors: HashMap::from([("get_members", error.clone())]),
                ..StubSyncStorage::healthy()
            },
            "sync",
        )
        .await;
        let code = if error == StorageError::SpaceNotFound {
            ERR_CODE_NOT_FOUND
        } else {
            ERR_CODE_INTERNAL
        };
        for method in ["epoch.begin", "epoch.complete", "membership.list"] {
            session
                .error(method, &request(method, &test_personal_space_id()), code)
                .await;
        }
        let mut session = Session::new(
            StubSyncStorage {
                operation_errors: HashMap::from([("get_space", error)]),
                ..StubSyncStorage::healthy()
            },
            "sync",
        )
        .await;
        session
            .error(
                "membership.list",
                &request("membership.list", &test_personal_space_id()),
                code,
            )
            .await;
    }
}

#[tokio::test]
async fn invitation_rpcs_reject_malformed_ids_and_pagination() {
    let mut session = Session::new(StubSyncStorage::healthy(), "sync").await;
    for method in [
        "invitation.create",
        "invitation.list",
        "invitation.get",
        "invitation.delete",
    ] {
        session
            .error(
                method,
                &serde_json::json!({"mailbox_id":4,"limit":"bad","id":4,"after":4}),
                ERR_CODE_INVALID_PARAMS,
            )
            .await;
    }
    session
        .error(
            "invitation.list",
            &serde_json::json!({"after":"invalid"}),
            ERR_CODE_BAD_REQUEST,
        )
        .await;
    for method in ["invitation.get", "invitation.delete"] {
        session
            .error(
                method,
                &serde_json::json!({"id":"invalid"}),
                ERR_CODE_BAD_REQUEST,
            )
            .await;
    }
    session
        .error(
            "invitation.create",
            &serde_json::json!({"mailbox_id":"","payload":"encrypted"}),
            ERR_CODE_BAD_REQUEST,
        )
        .await;
    session.error("invitation.create",&serde_json::json!({"mailbox_id":TEST_MAILBOX_ID,"payload":"encrypted","server":"peer.example.com"}),ERR_CODE_BAD_REQUEST).await;
    assert!(session
        .storage
        .invitation_list_calls
        .lock()
        .await
        .is_empty());
}

#[tokio::test]
async fn invitation_pagination_caps_limit_and_passes_cursor_and_authenticated_mailbox() {
    let mut session = Session::new(StubSyncStorage::healthy(), "sync").await;
    let cursor = Uuid::new_v4();
    for (requested, expected) in [
        (-1, 50),
        (0, 50),
        (1, 1),
        (200, 200),
        (201, 200),
        (i32::MAX, 200),
    ] {
        let _: InvitationListResult = session
            .result(
                "invitation.list",
                &serde_json::json!({"limit":requested,"after":cursor.to_string()}),
            )
            .await;
        assert_eq!(
            session.storage.invitation_list_calls.lock().await.last(),
            Some(&(TEST_MAILBOX_ID.to_owned(), expected, Some(cursor)))
        );
    }
}

#[tokio::test]
async fn invitation_storage_failures_are_internal_instead_of_not_found() {
    let mut session = Session::new(
        StubSyncStorage {
            operation_errors: HashMap::from([
                ("list_invitations", StorageError::Unavailable),
                ("get_invitation", StorageError::Unavailable),
            ]),
            invitation_delete_error: Some(StorageError::Unavailable),
            ..StubSyncStorage::healthy()
        },
        "sync",
    )
    .await;
    session
        .error("invitation.list", &serde_json::json!({}), ERR_CODE_INTERNAL)
        .await;
    for method in ["invitation.get", "invitation.delete"] {
        session
            .error(
                method,
                &serde_json::json!({"id":Uuid::new_v4().to_string()}),
                ERR_CODE_INTERNAL,
            )
            .await;
    }
}

#[tokio::test]
async fn invitation_invalid_timestamps_report_internal_without_partial_results() {
    let mut invitation = test_invitation(Uuid::new_v4(), TEST_MAILBOX_ID, "encrypted");
    invitation.created_at = SystemTime::UNIX_EPOCH - Duration::from_secs(62_198_755_200);
    let id = invitation.id;
    let mut session = Session::new(
        StubSyncStorage {
            created_invitation_override: Some(invitation.clone()),
            invitations: vec![
                test_invitation(Uuid::new_v4(), TEST_MAILBOX_ID, "valid"),
                invitation,
            ],
            ..StubSyncStorage::healthy()
        },
        "sync",
    )
    .await;
    session
        .error(
            "invitation.create",
            &serde_json::json!({"mailbox_id":TEST_MAILBOX_ID,"payload":"encrypted"}),
            ERR_CODE_INTERNAL,
        )
        .await;
    session
        .error("invitation.list", &serde_json::json!({}), ERR_CODE_INTERNAL)
        .await;
    session
        .error(
            "invitation.get",
            &serde_json::json!({"id":id.to_string()}),
            ERR_CODE_INTERNAL,
        )
        .await;
}
