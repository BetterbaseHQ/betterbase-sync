use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use http::header::SEC_WEBSOCKET_PROTOCOL;
use http::{HeaderValue, StatusCode};
use less_sync_auth::{AuthContext, AuthError, TokenValidator};
use less_sync_realtime::broker::{BrokerConfig, MultiBroker};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use tokio::task::JoinHandle;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{Error as WsError, Message as WsMessage};
use uuid::Uuid;

use super::storage::SubscribedSpaceState;
use super::SyncStorage;
use crate::{router, ApiState, HealthCheck};

type TestSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

struct StubHealth;

#[async_trait]
impl HealthCheck for StubHealth {
    async fn ping(&self) -> Result<(), less_sync_storage::StorageError> {
        Ok(())
    }
}

struct StubValidator {
    tokens: HashMap<String, AuthContext>,
}

impl StubValidator {
    fn with_scope(scope: &'static str) -> Self {
        Self::with_token_scopes(&[("valid-token", scope)])
    }

    fn with_token_scopes(tokens: &[(&str, &str)]) -> Self {
        let mut configured = HashMap::with_capacity(tokens.len());
        for (token, scope) in tokens {
            configured.insert((*token).to_owned(), test_auth_context(scope));
        }
        Self { tokens: configured }
    }
}

#[async_trait]
impl TokenValidator for StubValidator {
    async fn validate_token(&self, token: &str) -> Result<AuthContext, AuthError> {
        self.tokens
            .get(token)
            .cloned()
            .ok_or(AuthError::InvalidToken)
    }
}

struct StubSyncStorage {
    fail_for: HashSet<Uuid>,
    create_error: Option<less_sync_storage::StorageError>,
    create_key_generation: i32,
    push_result: less_sync_storage::PushResult,
    pull_result: less_sync_storage::PullResult,
}

impl StubSyncStorage {
    fn healthy() -> Self {
        Self {
            fail_for: HashSet::new(),
            create_error: None,
            create_key_generation: 1,
            push_result: less_sync_storage::PushResult {
                ok: true,
                cursor: 77,
                deleted_file_ids: Vec::new(),
            },
            pull_result: less_sync_storage::PullResult {
                entries: vec![less_sync_storage::PullEntry {
                    kind: less_sync_storage::PullEntryKind::Record,
                    cursor: 101,
                    record: Some(less_sync_core::protocol::Change {
                        id: Uuid::new_v4().to_string(),
                        blob: Some(b"record-blob".to_vec()),
                        cursor: 101,
                        wrapped_dek: Some(vec![0xAA; 44]),
                        deleted: false,
                    }),
                    member: None,
                    file: None,
                }],
                record_count: 1,
                cursor: 101,
            },
        }
    }

    fn with_create_error(error: less_sync_storage::StorageError) -> Self {
        Self {
            create_error: Some(error),
            ..Self::healthy()
        }
    }
}

#[async_trait]
impl SyncStorage for StubSyncStorage {
    async fn get_space(
        &self,
        space_id: Uuid,
    ) -> Result<less_sync_core::protocol::Space, less_sync_storage::StorageError> {
        if self.fail_for.contains(&space_id) {
            return Err(less_sync_storage::StorageError::Unavailable);
        }

        if space_id != test_personal_space_uuid() {
            return Err(less_sync_storage::StorageError::SpaceNotFound);
        }

        Ok(less_sync_core::protocol::Space {
            id: space_id.to_string(),
            client_id: "client-1".to_owned(),
            root_public_key: None,
            key_generation: 3,
            min_key_generation: 0,
            metadata_version: 0,
            cursor: 42,
            rewrap_epoch: Some(2),
            home_server: None,
        })
    }

    async fn create_space(
        &self,
        space_id: Uuid,
        client_id: &str,
        root_public_key: Option<&[u8]>,
    ) -> Result<less_sync_core::protocol::Space, less_sync_storage::StorageError> {
        if self.fail_for.contains(&space_id) {
            return Err(less_sync_storage::StorageError::Unavailable);
        }
        if let Some(error) = &self.create_error {
            return Err(error.clone());
        }

        Ok(less_sync_core::protocol::Space {
            id: space_id.to_string(),
            client_id: client_id.to_owned(),
            root_public_key: root_public_key.map(ToOwned::to_owned),
            key_generation: self.create_key_generation,
            min_key_generation: 0,
            metadata_version: 0,
            cursor: 0,
            rewrap_epoch: None,
            home_server: None,
        })
    }

    async fn get_or_create_space(
        &self,
        space_id: Uuid,
        _client_id: &str,
    ) -> Result<SubscribedSpaceState, less_sync_storage::StorageError> {
        if self.fail_for.contains(&space_id) {
            return Err(less_sync_storage::StorageError::Unavailable);
        }

        Ok(SubscribedSpaceState {
            cursor: 42,
            key_generation: 3,
            rewrap_epoch: Some(2),
        })
    }

    async fn push(
        &self,
        space_id: Uuid,
        _changes: &[less_sync_core::protocol::Change],
    ) -> Result<less_sync_storage::PushResult, less_sync_storage::StorageError> {
        if self.fail_for.contains(&space_id) {
            return Err(less_sync_storage::StorageError::Unavailable);
        }
        Ok(self.push_result.clone())
    }

    async fn pull(
        &self,
        space_id: Uuid,
        _since: i64,
    ) -> Result<less_sync_storage::PullResult, less_sync_storage::StorageError> {
        if self.fail_for.contains(&space_id) {
            return Err(less_sync_storage::StorageError::Unavailable);
        }
        Ok(self.pull_result.clone())
    }
}

#[tokio::test]
async fn websocket_rejects_wrong_subprotocol() {
    let server = spawn_server(base_state_with_ws(Duration::from_secs(1), "sync")).await;
    let request = ws_request(server.addr, Some("wrong-protocol"));

    let error = connect_async(request)
        .await
        .expect_err("wrong subprotocol should be rejected");
    assert_http_status(error, StatusCode::BAD_REQUEST);

    server.handle.abort();
}

#[tokio::test]
async fn websocket_rejects_missing_subprotocol() {
    let server = spawn_server(base_state_with_ws(Duration::from_secs(1), "sync")).await;
    let request = ws_request(server.addr, None);

    let error = connect_async(request)
        .await
        .expect_err("missing subprotocol should be rejected");
    assert_http_status(error, StatusCode::BAD_REQUEST);

    server.handle.abort();
}

#[tokio::test]
async fn websocket_auth_timeout_closes_with_auth_failed() {
    let server = spawn_server(base_state_with_ws(Duration::from_millis(100), "sync")).await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");

    let close_code = expect_close_code(&mut socket).await;
    assert_eq!(
        close_code,
        less_sync_core::protocol::CLOSE_AUTH_FAILED as u16
    );

    server.handle.abort();
}

#[tokio::test]
async fn websocket_non_auth_first_frame_closes_with_auth_failed() {
    let server = spawn_server(base_state_with_ws(Duration::from_secs(1), "sync")).await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");

    let frame = serde_cbor::to_vec(&serde_json::json!({
        "type": less_sync_core::protocol::RPC_REQUEST,
        "method": "subscribe",
        "id": "req-1",
        "params": {}
    }))
    .expect("encode frame");
    socket
        .send(WsMessage::Binary(frame.into()))
        .await
        .expect("send frame");

    let close_code = expect_close_code(&mut socket).await;
    assert_eq!(
        close_code,
        less_sync_core::protocol::CLOSE_AUTH_FAILED as u16
    );

    server.handle.abort();
}

#[tokio::test]
async fn websocket_text_after_auth_closes_with_protocol_error() {
    let server = spawn_server(base_state_with_ws(Duration::from_secs(1), "sync")).await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");

    send_auth(&mut socket).await;
    socket
        .send(WsMessage::Text("hello".into()))
        .await
        .expect("send text frame");

    let close_code = expect_close_code(&mut socket).await;
    assert_eq!(
        close_code,
        less_sync_core::protocol::CLOSE_PROTOCOL_ERROR as u16
    );

    server.handle.abort();
}

#[tokio::test]
async fn websocket_invalid_cbor_after_auth_closes_with_protocol_error() {
    let server = spawn_server(base_state_with_ws(Duration::from_secs(1), "sync")).await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");

    send_auth(&mut socket).await;
    socket
        .send(WsMessage::Binary(vec![0xFF, 0xFF, 0xFF].into()))
        .await
        .expect("send binary frame");

    let close_code = expect_close_code(&mut socket).await;
    assert_eq!(
        close_code,
        less_sync_core::protocol::CLOSE_PROTOCOL_ERROR as u16
    );

    server.handle.abort();
}

#[tokio::test]
async fn websocket_empty_binary_after_auth_closes_with_protocol_error() {
    let server = spawn_server(base_state_with_ws(Duration::from_secs(1), "sync")).await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");

    send_auth(&mut socket).await;
    socket
        .send(WsMessage::Binary(Vec::new().into()))
        .await
        .expect("send binary frame");

    let close_code = expect_close_code(&mut socket).await;
    assert_eq!(
        close_code,
        less_sync_core::protocol::CLOSE_PROTOCOL_ERROR as u16
    );

    server.handle.abort();
}

#[tokio::test]
async fn websocket_unknown_method_returns_method_not_found() {
    let server = spawn_server(base_state_with_ws(Duration::from_secs(1), "sync")).await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");

    send_auth(&mut socket).await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "req-1",
            "method": "nonexistent.method",
            "params": {}
        }),
    )
    .await;

    let response = read_error_response(&mut socket).await;
    assert_eq!(response.frame_type, less_sync_core::protocol::RPC_RESPONSE);
    assert_eq!(response.id, "req-1");
    assert_eq!(
        response.error.code,
        less_sync_core::protocol::ERR_CODE_METHOD_NOT_FOUND
    );

    server.handle.abort();
}

#[tokio::test]
async fn websocket_token_refresh_returns_error_for_invalid_token() {
    let server = spawn_server(base_state_with_ws(Duration::from_secs(1), "sync")).await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");

    send_auth(&mut socket).await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "refresh-1",
            "method": "token.refresh",
            "params": { "token": "unknown-token" }
        }),
    )
    .await;

    let response: RpcResultResponse<less_sync_core::protocol::TokenRefreshResult> =
        read_result_response(&mut socket).await;
    assert_eq!(response.id, "refresh-1");
    assert!(!response.result.ok);
    assert_eq!(response.result.error, "invalid auth token");

    server.handle.abort();
}

#[tokio::test]
async fn websocket_token_refresh_requires_sync_scope_and_keeps_previous_auth() {
    let validator = Arc::new(StubValidator::with_token_scopes(&[
        ("valid-token", "sync"),
        ("refresh-no-sync", "files"),
    ]));
    let server = spawn_server(
        base_state_with_ws_validator(Duration::from_secs(1), validator)
            .with_sync_storage_adapter(Arc::new(StubSyncStorage::healthy())),
    )
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");
    let space_id = test_personal_space_id();
    let record_id = Uuid::new_v4().to_string();

    send_auth(&mut socket).await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "refresh-2",
            "method": "token.refresh",
            "params": { "token": "refresh-no-sync" }
        }),
    )
    .await;

    let response: RpcResultResponse<less_sync_core::protocol::TokenRefreshResult> =
        read_result_response(&mut socket).await;
    assert_eq!(response.id, "refresh-2");
    assert!(!response.result.ok);
    assert_eq!(response.result.error, "sync scope required");

    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "push-after-refresh-fail",
            "method": "push",
            "params": {
                "space": space_id,
                "changes": [{
                    "id": record_id,
                    "blob": [1,2,3],
                    "expected_cursor": 0,
                    "dek": vec![170; 44]
                }]
            }
        }),
    )
    .await;

    let push: RpcResultResponse<less_sync_core::protocol::PushRpcResult> =
        read_result_response(&mut socket).await;
    assert_eq!(push.id, "push-after-refresh-fail");
    assert!(push.result.ok);

    server.handle.abort();
}

#[tokio::test]
async fn websocket_token_refresh_accepts_new_valid_token() {
    let validator = Arc::new(StubValidator::with_token_scopes(&[
        ("valid-token", "sync"),
        ("refresh-token", "sync"),
    ]));
    let server = spawn_server(base_state_with_ws_validator(
        Duration::from_secs(1),
        validator,
    ))
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");

    send_auth(&mut socket).await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "refresh-3",
            "method": "token.refresh",
            "params": { "token": "refresh-token" }
        }),
    )
    .await;

    let response: RpcResultResponse<less_sync_core::protocol::TokenRefreshResult> =
        read_result_response(&mut socket).await;
    assert_eq!(response.id, "refresh-3");
    assert!(response.result.ok);
    assert!(response.result.error.is_empty());

    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "refresh-post-unknown",
            "method": "nonexistent.method",
            "params": {}
        }),
    )
    .await;
    let unknown = read_error_response(&mut socket).await;
    assert_eq!(unknown.id, "refresh-post-unknown");

    server.handle.abort();
}

#[tokio::test]
async fn websocket_token_refresh_rejects_identity_mismatch() {
    let mut tokens = HashMap::new();
    tokens.insert("valid-token".to_owned(), test_auth_context("sync"));
    let mut mismatched = test_auth_context("sync");
    mismatched.user_id = "user-2".to_owned();
    tokens.insert("refresh-mismatch".to_owned(), mismatched);

    let server = spawn_server(
        base_state_with_ws_validator(Duration::from_secs(1), Arc::new(StubValidator { tokens }))
            .with_sync_storage_adapter(Arc::new(StubSyncStorage::healthy())),
    )
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");
    let space_id = test_personal_space_id();
    let record_id = Uuid::new_v4().to_string();

    send_auth(&mut socket).await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "refresh-4",
            "method": "token.refresh",
            "params": { "token": "refresh-mismatch" }
        }),
    )
    .await;

    let response: RpcResultResponse<less_sync_core::protocol::TokenRefreshResult> =
        read_result_response(&mut socket).await;
    assert_eq!(response.id, "refresh-4");
    assert!(!response.result.ok);
    assert_eq!(response.result.error, "token identity mismatch");

    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "push-after-refresh-mismatch",
            "method": "push",
            "params": {
                "space": space_id,
                "changes": [{
                    "id": record_id,
                    "blob": [1,2,3],
                    "expected_cursor": 0,
                    "dek": vec![170; 44]
                }]
            }
        }),
    )
    .await;

    let push: RpcResultResponse<less_sync_core::protocol::PushRpcResult> =
        read_result_response(&mut socket).await;
    assert_eq!(push.id, "push-after-refresh-mismatch");
    assert!(push.result.ok);

    server.handle.abort();
}

#[tokio::test]
async fn websocket_space_create_returns_id_and_key_generation() {
    let server = spawn_server(base_state_with_ws_and_storage(
        Duration::from_secs(1),
        "sync",
        Arc::new(StubSyncStorage::healthy()),
    ))
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");
    let space_id = Uuid::new_v4().to_string();

    send_auth(&mut socket).await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "space-create-1",
            "method": "space.create",
            "params": {
                "id": space_id,
                "root_public_key": [1, 2, 3]
            }
        }),
    )
    .await;

    let response: RpcResultResponse<less_sync_core::protocol::SpaceCreateResult> =
        read_result_response(&mut socket).await;
    assert_eq!(response.id, "space-create-1");
    assert_eq!(response.result.id, space_id);
    assert_eq!(response.result.key_generation, 1);

    server.handle.abort();
}

#[tokio::test]
async fn websocket_space_create_invalid_space_id_returns_bad_request() {
    let server = spawn_server(base_state_with_ws_and_storage(
        Duration::from_secs(1),
        "sync",
        Arc::new(StubSyncStorage::healthy()),
    ))
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");

    send_auth(&mut socket).await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "space-create-2",
            "method": "space.create",
            "params": {
                "id": "not-a-uuid",
                "root_public_key": [1, 2, 3]
            }
        }),
    )
    .await;

    let response = read_error_response(&mut socket).await;
    assert_eq!(response.id, "space-create-2");
    assert_eq!(
        response.error.code,
        less_sync_core::protocol::ERR_CODE_BAD_REQUEST
    );

    server.handle.abort();
}

#[tokio::test]
async fn websocket_space_create_empty_root_public_key_returns_bad_request() {
    let server = spawn_server(base_state_with_ws_and_storage(
        Duration::from_secs(1),
        "sync",
        Arc::new(StubSyncStorage::healthy()),
    ))
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");

    send_auth(&mut socket).await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "space-create-2b",
            "method": "space.create",
            "params": {
                "id": Uuid::new_v4().to_string(),
                "root_public_key": []
            }
        }),
    )
    .await;

    let response = read_error_response(&mut socket).await;
    assert_eq!(response.id, "space-create-2b");
    assert_eq!(
        response.error.code,
        less_sync_core::protocol::ERR_CODE_BAD_REQUEST
    );

    server.handle.abort();
}

#[tokio::test]
async fn websocket_space_create_conflict_returns_conflict_error() {
    let server = spawn_server(base_state_with_ws_and_storage(
        Duration::from_secs(1),
        "sync",
        Arc::new(StubSyncStorage::with_create_error(
            less_sync_storage::StorageError::SpaceExists,
        )),
    ))
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");

    send_auth(&mut socket).await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "space-create-3",
            "method": "space.create",
            "params": {
                "id": Uuid::new_v4().to_string(),
                "root_public_key": [1, 2, 3]
            }
        }),
    )
    .await;

    let response = read_error_response(&mut socket).await;
    assert_eq!(response.id, "space-create-3");
    assert_eq!(
        response.error.code,
        less_sync_core::protocol::ERR_CODE_CONFLICT
    );

    server.handle.abort();
}

#[tokio::test]
async fn websocket_space_create_without_sync_storage_returns_internal_error() {
    let server = spawn_server(base_state_with_ws(Duration::from_secs(1), "sync")).await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");

    send_auth(&mut socket).await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "space-create-4",
            "method": "space.create",
            "params": {
                "id": Uuid::new_v4().to_string(),
                "root_public_key": [1, 2, 3]
            }
        }),
    )
    .await;

    let response = read_error_response(&mut socket).await;
    assert_eq!(response.id, "space-create-4");
    assert_eq!(
        response.error.code,
        less_sync_core::protocol::ERR_CODE_INTERNAL
    );

    server.handle.abort();
}

#[tokio::test]
async fn websocket_subscribe_returns_space_metadata() {
    let server = spawn_server(base_state_with_ws_and_storage(
        Duration::from_secs(1),
        "sync",
        Arc::new(StubSyncStorage::healthy()),
    ))
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");
    let space_id = test_personal_space_id();

    send_auth(&mut socket).await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "sub-1",
            "method": "subscribe",
            "params": {
                "spaces": [{ "id": space_id, "since": 0 }]
            }
        }),
    )
    .await;

    let response: RpcResultResponse<less_sync_core::protocol::SubscribeResult> =
        read_result_response(&mut socket).await;
    assert_eq!(response.id, "sub-1");
    assert_eq!(response.result.spaces.len(), 1);
    assert_eq!(response.result.spaces[0].cursor, 42);
    assert_eq!(response.result.spaces[0].key_generation, 3);
    assert_eq!(response.result.spaces[0].rewrap_epoch, Some(2));
    assert!(response.result.errors.is_empty());

    server.handle.abort();
}

#[tokio::test]
async fn websocket_subscribe_invalid_space_id_is_reported_in_result_errors() {
    let server = spawn_server(base_state_with_ws_and_storage(
        Duration::from_secs(1),
        "sync",
        Arc::new(StubSyncStorage::healthy()),
    ))
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");

    send_auth(&mut socket).await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "sub-2",
            "method": "subscribe",
            "params": {
                "spaces": [{ "id": "not-a-uuid", "since": 0 }]
            }
        }),
    )
    .await;

    let response: RpcResultResponse<less_sync_core::protocol::SubscribeResult> =
        read_result_response(&mut socket).await;
    assert_eq!(response.id, "sub-2");
    assert!(response.result.spaces.is_empty());
    assert_eq!(response.result.errors.len(), 1);
    assert_eq!(
        response.result.errors[0].error,
        less_sync_core::protocol::ERR_CODE_BAD_REQUEST
    );

    server.handle.abort();
}

#[tokio::test]
async fn websocket_subscribe_non_personal_space_without_ucan_reports_forbidden() {
    let server = spawn_server(base_state_with_ws_and_storage(
        Duration::from_secs(1),
        "sync",
        Arc::new(StubSyncStorage::healthy()),
    ))
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");

    send_auth(&mut socket).await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "sub-forbidden-1",
            "method": "subscribe",
            "params": {
                "spaces": [{ "id": Uuid::new_v4().to_string(), "since": 0 }]
            }
        }),
    )
    .await;

    let response: RpcResultResponse<less_sync_core::protocol::SubscribeResult> =
        read_result_response(&mut socket).await;
    assert_eq!(response.id, "sub-forbidden-1");
    assert!(response.result.spaces.is_empty());
    assert_eq!(response.result.errors.len(), 1);
    assert_eq!(
        response.result.errors[0].error,
        less_sync_core::protocol::ERR_CODE_FORBIDDEN
    );

    server.handle.abort();
}

#[tokio::test]
async fn websocket_subscribe_without_sync_storage_returns_internal_error() {
    let server = spawn_server(base_state_with_ws(Duration::from_secs(1), "sync")).await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");

    send_auth(&mut socket).await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "sub-3",
            "method": "subscribe",
            "params": { "spaces": [] }
        }),
    )
    .await;

    let response = read_error_response(&mut socket).await;
    assert_eq!(response.id, "sub-3");
    assert_eq!(
        response.error.code,
        less_sync_core::protocol::ERR_CODE_INTERNAL
    );

    server.handle.abort();
}

#[tokio::test]
async fn websocket_push_returns_cursor_on_success() {
    let server = spawn_server(base_state_with_ws_and_storage(
        Duration::from_secs(1),
        "sync",
        Arc::new(StubSyncStorage::healthy()),
    ))
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");
    let space_id = test_personal_space_id();
    let record_id = Uuid::new_v4().to_string();

    send_auth(&mut socket).await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "push-1",
            "method": "push",
            "params": {
                "space": space_id,
                "changes": [{
                    "id": record_id,
                    "blob": [1,2,3],
                    "expected_cursor": 0,
                    "dek": vec![170; 44]
                }]
            }
        }),
    )
    .await;

    let response: RpcResultResponse<less_sync_core::protocol::PushRpcResult> =
        read_result_response(&mut socket).await;
    assert_eq!(response.id, "push-1");
    assert!(response.result.ok);
    assert_eq!(response.result.cursor, 77);

    server.handle.abort();
}

#[tokio::test]
async fn websocket_push_invalid_space_id_returns_bad_request_result() {
    let server = spawn_server(base_state_with_ws_and_storage(
        Duration::from_secs(1),
        "sync",
        Arc::new(StubSyncStorage::healthy()),
    ))
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");
    let record_id = Uuid::new_v4().to_string();

    send_auth(&mut socket).await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "push-2",
            "method": "push",
            "params": {
                "space": "not-a-uuid",
                "changes": [{
                    "id": record_id,
                    "blob": [1,2,3],
                    "expected_cursor": 0,
                    "dek": vec![170; 44]
                }]
            }
        }),
    )
    .await;

    let response: RpcResultResponse<less_sync_core::protocol::PushRpcResult> =
        read_result_response(&mut socket).await;
    assert!(!response.result.ok);
    assert_eq!(
        response.result.error,
        less_sync_core::protocol::ERR_CODE_BAD_REQUEST
    );

    server.handle.abort();
}

#[tokio::test]
async fn websocket_push_non_personal_space_without_ucan_returns_forbidden() {
    let server = spawn_server(base_state_with_ws_and_storage(
        Duration::from_secs(1),
        "sync",
        Arc::new(StubSyncStorage::healthy()),
    ))
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");
    let record_id = Uuid::new_v4().to_string();

    send_auth(&mut socket).await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "push-forbidden-1",
            "method": "push",
            "params": {
                "space": Uuid::new_v4().to_string(),
                "changes": [{
                    "id": record_id,
                    "blob": [1,2,3],
                    "expected_cursor": 0,
                    "dek": vec![170; 44]
                }]
            }
        }),
    )
    .await;

    let response: RpcResultResponse<less_sync_core::protocol::PushRpcResult> =
        read_result_response(&mut socket).await;
    assert_eq!(response.id, "push-forbidden-1");
    assert!(!response.result.ok);
    assert_eq!(
        response.result.error,
        less_sync_core::protocol::ERR_CODE_FORBIDDEN
    );

    server.handle.abort();
}

#[tokio::test]
async fn websocket_pull_streams_chunks_and_terminal_result() {
    let server = spawn_server(base_state_with_ws_and_storage(
        Duration::from_secs(1),
        "sync",
        Arc::new(StubSyncStorage::healthy()),
    ))
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");
    let space_id = test_personal_space_id();

    send_auth(&mut socket).await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "pull-1",
            "method": "pull",
            "params": {
                "spaces": [{ "id": space_id, "since": 100, "ucan": "" }]
            }
        }),
    )
    .await;

    let begin: RpcChunkResponse<less_sync_core::protocol::WsPullBeginData> =
        read_chunk_response(&mut socket).await;
    assert_eq!(begin.id, "pull-1");
    assert_eq!(begin.name, "pull.begin");
    assert_eq!(begin.data.cursor, 101);

    let record: RpcChunkResponse<less_sync_core::protocol::WsPullRecordData> =
        read_chunk_response(&mut socket).await;
    assert_eq!(record.name, "pull.record");
    assert_eq!(record.data.cursor, 101);

    let commit: RpcChunkResponse<less_sync_core::protocol::WsPullCommitData> =
        read_chunk_response(&mut socket).await;
    assert_eq!(commit.name, "pull.commit");
    assert_eq!(commit.data.count, 1);

    let result: RpcResultResponse<PullSummaryResult> = read_result_response(&mut socket).await;
    assert_eq!(result.id, "pull-1");
    assert_eq!(result.result.chunks, 3);

    server.handle.abort();
}

#[tokio::test]
async fn websocket_pull_skips_unauthorized_space_entries() {
    let server = spawn_server(base_state_with_ws_and_storage(
        Duration::from_secs(1),
        "sync",
        Arc::new(StubSyncStorage::healthy()),
    ))
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");
    let forbidden_space = Uuid::new_v4().to_string();

    send_auth(&mut socket).await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "pull-multi-1",
            "method": "pull",
            "params": {
                "spaces": [
                    { "id": test_personal_space_id(), "since": 100, "ucan": "" },
                    { "id": forbidden_space, "since": 100, "ucan": "" }
                ]
            }
        }),
    )
    .await;

    let begin: RpcChunkResponse<less_sync_core::protocol::WsPullBeginData> =
        read_chunk_response(&mut socket).await;
    assert_eq!(begin.id, "pull-multi-1");
    assert_eq!(begin.data.space, test_personal_space_id());

    let record: RpcChunkResponse<less_sync_core::protocol::WsPullRecordData> =
        read_chunk_response(&mut socket).await;
    assert_eq!(record.data.space, test_personal_space_id());

    let commit: RpcChunkResponse<less_sync_core::protocol::WsPullCommitData> =
        read_chunk_response(&mut socket).await;
    assert_eq!(commit.data.space, test_personal_space_id());
    assert_eq!(commit.data.count, 1);

    let result: RpcResultResponse<PullSummaryResult> = read_result_response(&mut socket).await;
    assert_eq!(result.id, "pull-multi-1");
    assert_eq!(result.result.chunks, 3);

    server.handle.abort();
}

#[tokio::test]
async fn websocket_push_broadcasts_sync_to_other_subscribers() {
    let broker = Arc::new(MultiBroker::new(BrokerConfig::default()));
    let server = spawn_server(base_state_with_ws_storage_and_broker(
        Duration::from_secs(1),
        "sync",
        Arc::new(StubSyncStorage::healthy()),
        broker,
    ))
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut sender_socket, _) = connect_async(request.clone())
        .await
        .expect("connect websocket sender");
    let (mut watcher_socket, _) = connect_async(request)
        .await
        .expect("connect websocket watcher");
    let space_id = test_personal_space_id();
    let record_id = Uuid::new_v4().to_string();

    send_auth(&mut sender_socket).await;
    send_auth(&mut watcher_socket).await;

    send_binary_frame(
        &mut sender_socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "sub-sender",
            "method": "subscribe",
            "params": {
                "spaces": [{ "id": space_id.clone(), "since": 0 }]
            }
        }),
    )
    .await;
    let _: RpcResultResponse<less_sync_core::protocol::SubscribeResult> =
        read_result_response(&mut sender_socket).await;

    send_binary_frame(
        &mut watcher_socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "sub-watcher",
            "method": "subscribe",
            "params": {
                "spaces": [{ "id": space_id.clone(), "since": 0 }]
            }
        }),
    )
    .await;
    let _: RpcResultResponse<less_sync_core::protocol::SubscribeResult> =
        read_result_response(&mut watcher_socket).await;

    send_binary_frame(
        &mut sender_socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "push-sync-1",
            "method": "push",
            "params": {
                "space": space_id.clone(),
                "changes": [{
                    "id": record_id.clone(),
                    "blob": [7,8,9],
                    "expected_cursor": 0,
                    "dek": vec![170; 44]
                }]
            }
        }),
    )
    .await;

    let response: RpcResultResponse<less_sync_core::protocol::PushRpcResult> =
        read_result_response(&mut sender_socket).await;
    assert_eq!(response.id, "push-sync-1");
    assert!(response.result.ok);

    let notification: RpcNotificationResponse<less_sync_core::protocol::WsSyncData> =
        read_notification_response(&mut watcher_socket).await;
    assert_eq!(notification.method, "sync");
    assert_eq!(notification.params.space, space_id);
    assert_eq!(notification.params.cursor, 77);
    assert_eq!(notification.params.records.len(), 1);
    assert_eq!(notification.params.records[0].id, record_id);
    assert_eq!(notification.params.records[0].blob, Some(vec![7, 8, 9]));

    let sender_frame = tokio::time::timeout(Duration::from_millis(250), sender_socket.next()).await;
    assert!(
        sender_frame.is_err(),
        "sender should not receive sync notification"
    );

    server.handle.abort();
}

#[tokio::test]
async fn websocket_unsubscribe_notification_stops_sync_broadcasts() {
    let broker = Arc::new(MultiBroker::new(BrokerConfig::default()));
    let server = spawn_server(base_state_with_ws_storage_and_broker(
        Duration::from_secs(1),
        "sync",
        Arc::new(StubSyncStorage::healthy()),
        broker,
    ))
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut sender_socket, _) = connect_async(request.clone())
        .await
        .expect("connect websocket sender");
    let (mut watcher_socket, _) = connect_async(request)
        .await
        .expect("connect websocket watcher");
    let space_id = test_personal_space_id();
    let record_id = Uuid::new_v4().to_string();

    send_auth(&mut sender_socket).await;
    send_auth(&mut watcher_socket).await;

    send_binary_frame(
        &mut sender_socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "sub-sender-2",
            "method": "subscribe",
            "params": {
                "spaces": [{ "id": space_id.clone(), "since": 0 }]
            }
        }),
    )
    .await;
    let _: RpcResultResponse<less_sync_core::protocol::SubscribeResult> =
        read_result_response(&mut sender_socket).await;

    send_binary_frame(
        &mut watcher_socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "sub-watcher-2",
            "method": "subscribe",
            "params": {
                "spaces": [{ "id": space_id.clone(), "since": 0 }]
            }
        }),
    )
    .await;
    let _: RpcResultResponse<less_sync_core::protocol::SubscribeResult> =
        read_result_response(&mut watcher_socket).await;

    send_binary_frame(
        &mut watcher_socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_NOTIFICATION,
            "method": "unsubscribe",
            "params": { "spaces": [space_id.clone()] }
        }),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    send_binary_frame(
        &mut sender_socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "push-sync-2",
            "method": "push",
            "params": {
                "space": space_id.clone(),
                "changes": [{
                    "id": record_id.clone(),
                    "blob": [1,2,3],
                    "expected_cursor": 0,
                    "dek": vec![170; 44]
                }]
            }
        }),
    )
    .await;
    let _: RpcResultResponse<less_sync_core::protocol::PushRpcResult> =
        read_result_response(&mut sender_socket).await;

    let watcher_frame =
        tokio::time::timeout(Duration::from_millis(300), watcher_socket.next()).await;
    assert!(
        watcher_frame.is_err(),
        "unsubscribed watcher should not receive sync notification"
    );

    server.handle.abort();
}

#[tokio::test]
async fn websocket_subscribe_with_presence_returns_existing_peers() {
    let broker = Arc::new(MultiBroker::new(BrokerConfig::default()));
    let server = spawn_server(base_state_with_ws_storage_and_broker(
        Duration::from_secs(1),
        "sync",
        Arc::new(StubSyncStorage::healthy()),
        broker,
    ))
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut sender_socket, _) = connect_async(request.clone())
        .await
        .expect("connect websocket sender");
    let (mut watcher_socket, _) = connect_async(request)
        .await
        .expect("connect websocket watcher");
    let space_id = test_personal_space_id();

    send_auth(&mut sender_socket).await;
    send_auth(&mut watcher_socket).await;

    send_binary_frame(
        &mut sender_socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "sub-presence-sender-1",
            "method": "subscribe",
            "params": {
                "spaces": [{ "id": space_id.clone(), "since": 0 }]
            }
        }),
    )
    .await;
    let _: RpcResultResponse<less_sync_core::protocol::SubscribeResult> =
        read_result_response(&mut sender_socket).await;

    send_binary_frame(
        &mut sender_socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_NOTIFICATION,
            "method": "presence.set",
            "params": {
                "space": space_id.clone(),
                "data": [9, 9, 9]
            }
        }),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    send_binary_frame(
        &mut watcher_socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "sub-presence-watcher-1",
            "method": "subscribe",
            "params": {
                "spaces": [{ "id": space_id, "since": 0, "presence": true }]
            }
        }),
    )
    .await;

    let response: RpcResultResponse<less_sync_core::protocol::SubscribeResult> =
        read_result_response(&mut watcher_socket).await;
    assert_eq!(response.id, "sub-presence-watcher-1");
    assert_eq!(response.result.spaces.len(), 1);
    assert_eq!(response.result.spaces[0].peers.len(), 1);
    assert!(!response.result.spaces[0].peers[0].peer.is_empty());
    assert_eq!(response.result.spaces[0].peers[0].data, vec![9, 9, 9]);

    server.handle.abort();
}

#[tokio::test]
async fn websocket_presence_set_broadcasts_to_other_subscribers() {
    let broker = Arc::new(MultiBroker::new(BrokerConfig::default()));
    let server = spawn_server(base_state_with_ws_storage_and_broker(
        Duration::from_secs(1),
        "sync",
        Arc::new(StubSyncStorage::healthy()),
        broker,
    ))
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut sender_socket, _) = connect_async(request.clone())
        .await
        .expect("connect websocket sender");
    let (mut watcher_socket, _) = connect_async(request)
        .await
        .expect("connect websocket watcher");
    let space_id = test_personal_space_id();

    send_auth(&mut sender_socket).await;
    send_auth(&mut watcher_socket).await;
    subscribe_socket_to_space(&mut sender_socket, "sub-presence-sender-2", &space_id).await;
    subscribe_socket_to_space(&mut watcher_socket, "sub-presence-watcher-2", &space_id).await;

    send_binary_frame(
        &mut sender_socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_NOTIFICATION,
            "method": "presence.set",
            "params": {
                "space": space_id.clone(),
                "data": [1, 2, 3, 4]
            }
        }),
    )
    .await;

    let notification: RpcNotificationResponse<less_sync_core::protocol::WsPresenceData> =
        read_notification_response(&mut watcher_socket).await;
    assert_eq!(notification.method, "presence");
    assert_eq!(notification.params.space, space_id);
    assert_eq!(notification.params.data, vec![1, 2, 3, 4]);
    assert!(!notification.params.peer.is_empty());

    let sender_frame = tokio::time::timeout(Duration::from_millis(250), sender_socket.next()).await;
    assert!(
        sender_frame.is_err(),
        "sender should not receive presence notification"
    );

    server.handle.abort();
}

#[tokio::test]
async fn websocket_presence_clear_broadcasts_leave_notification() {
    let broker = Arc::new(MultiBroker::new(BrokerConfig::default()));
    let server = spawn_server(base_state_with_ws_storage_and_broker(
        Duration::from_secs(1),
        "sync",
        Arc::new(StubSyncStorage::healthy()),
        broker,
    ))
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut sender_socket, _) = connect_async(request.clone())
        .await
        .expect("connect websocket sender");
    let (mut watcher_socket, _) = connect_async(request)
        .await
        .expect("connect websocket watcher");
    let space_id = test_personal_space_id();

    send_auth(&mut sender_socket).await;
    send_auth(&mut watcher_socket).await;
    subscribe_socket_to_space(&mut sender_socket, "sub-presence-sender-3", &space_id).await;
    subscribe_socket_to_space(&mut watcher_socket, "sub-presence-watcher-3", &space_id).await;

    send_binary_frame(
        &mut sender_socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_NOTIFICATION,
            "method": "presence.set",
            "params": {
                "space": space_id.clone(),
                "data": [8, 8]
            }
        }),
    )
    .await;

    let set_notification: RpcNotificationResponse<less_sync_core::protocol::WsPresenceData> =
        read_notification_response(&mut watcher_socket).await;
    assert_eq!(set_notification.method, "presence");

    send_binary_frame(
        &mut sender_socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_NOTIFICATION,
            "method": "presence.clear",
            "params": { "space": space_id.clone() }
        }),
    )
    .await;

    let leave_notification: RpcNotificationResponse<less_sync_core::protocol::WsPresenceLeaveData> =
        read_notification_response(&mut watcher_socket).await;
    assert_eq!(leave_notification.method, "presence.leave");
    assert_eq!(leave_notification.params.space, space_id);
    assert_eq!(leave_notification.params.peer, set_notification.params.peer);

    server.handle.abort();
}

#[tokio::test]
async fn websocket_unsubscribe_clears_presence_and_broadcasts_leave() {
    let broker = Arc::new(MultiBroker::new(BrokerConfig::default()));
    let server = spawn_server(base_state_with_ws_storage_and_broker(
        Duration::from_secs(1),
        "sync",
        Arc::new(StubSyncStorage::healthy()),
        broker,
    ))
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut sender_socket, _) = connect_async(request.clone())
        .await
        .expect("connect websocket sender");
    let (mut watcher_socket, _) = connect_async(request)
        .await
        .expect("connect websocket watcher");
    let space_id = test_personal_space_id();

    send_auth(&mut sender_socket).await;
    send_auth(&mut watcher_socket).await;
    subscribe_socket_to_space(&mut sender_socket, "sub-presence-sender-35", &space_id).await;
    subscribe_socket_to_space(&mut watcher_socket, "sub-presence-watcher-35", &space_id).await;

    send_binary_frame(
        &mut sender_socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_NOTIFICATION,
            "method": "presence.set",
            "params": {
                "space": space_id.clone(),
                "data": [2, 2]
            }
        }),
    )
    .await;

    let set_notification: RpcNotificationResponse<less_sync_core::protocol::WsPresenceData> =
        read_notification_response(&mut watcher_socket).await;
    assert_eq!(set_notification.method, "presence");

    send_binary_frame(
        &mut sender_socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_NOTIFICATION,
            "method": "unsubscribe",
            "params": { "spaces": [space_id.clone()] }
        }),
    )
    .await;

    let leave_notification: RpcNotificationResponse<less_sync_core::protocol::WsPresenceLeaveData> =
        read_notification_response(&mut watcher_socket).await;
    assert_eq!(leave_notification.method, "presence.leave");
    assert_eq!(leave_notification.params.space, space_id);
    assert_eq!(leave_notification.params.peer, set_notification.params.peer);

    server.handle.abort();
}

#[tokio::test]
async fn websocket_event_send_broadcasts_to_other_subscribers() {
    let broker = Arc::new(MultiBroker::new(BrokerConfig::default()));
    let server = spawn_server(base_state_with_ws_storage_and_broker(
        Duration::from_secs(1),
        "sync",
        Arc::new(StubSyncStorage::healthy()),
        broker,
    ))
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut sender_socket, _) = connect_async(request.clone())
        .await
        .expect("connect websocket sender");
    let (mut watcher_socket, _) = connect_async(request)
        .await
        .expect("connect websocket watcher");
    let space_id = test_personal_space_id();

    send_auth(&mut sender_socket).await;
    send_auth(&mut watcher_socket).await;
    subscribe_socket_to_space(&mut sender_socket, "sub-event-sender-1", &space_id).await;
    subscribe_socket_to_space(&mut watcher_socket, "sub-event-watcher-1", &space_id).await;

    send_binary_frame(
        &mut sender_socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_NOTIFICATION,
            "method": "event.send",
            "params": {
                "space": space_id.clone(),
                "data": [4, 5, 6]
            }
        }),
    )
    .await;

    let notification: RpcNotificationResponse<less_sync_core::protocol::WsEventData> =
        read_notification_response(&mut watcher_socket).await;
    assert_eq!(notification.method, "event");
    assert_eq!(notification.params.space, space_id);
    assert_eq!(notification.params.data, vec![4, 5, 6]);
    assert!(!notification.params.peer.is_empty());

    server.handle.abort();
}

#[tokio::test]
async fn websocket_presence_leave_broadcasts_when_peer_disconnects() {
    let broker = Arc::new(MultiBroker::new(BrokerConfig::default()));
    let server = spawn_server(base_state_with_ws_storage_and_broker(
        Duration::from_secs(1),
        "sync",
        Arc::new(StubSyncStorage::healthy()),
        broker,
    ))
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut sender_socket, _) = connect_async(request.clone())
        .await
        .expect("connect websocket sender");
    let (mut watcher_socket, _) = connect_async(request)
        .await
        .expect("connect websocket watcher");
    let space_id = test_personal_space_id();

    send_auth(&mut sender_socket).await;
    send_auth(&mut watcher_socket).await;
    subscribe_socket_to_space(&mut sender_socket, "sub-presence-sender-4", &space_id).await;
    subscribe_socket_to_space(&mut watcher_socket, "sub-presence-watcher-4", &space_id).await;

    send_binary_frame(
        &mut sender_socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_NOTIFICATION,
            "method": "presence.set",
            "params": {
                "space": space_id.clone(),
                "data": [1]
            }
        }),
    )
    .await;

    let set_notification: RpcNotificationResponse<less_sync_core::protocol::WsPresenceData> =
        read_notification_response(&mut watcher_socket).await;
    assert_eq!(set_notification.method, "presence");

    sender_socket
        .close(None)
        .await
        .expect("close sender socket");

    let leave_notification: RpcNotificationResponse<less_sync_core::protocol::WsPresenceLeaveData> =
        read_notification_response(&mut watcher_socket).await;
    assert_eq!(leave_notification.method, "presence.leave");
    assert_eq!(leave_notification.params.space, space_id);
    assert_eq!(leave_notification.params.peer, set_notification.params.peer);

    server.handle.abort();
}

#[tokio::test]
async fn websocket_presence_set_oversized_payload_is_ignored() {
    let broker = Arc::new(MultiBroker::new(BrokerConfig::default()));
    let server = spawn_server(base_state_with_ws_storage_and_broker(
        Duration::from_secs(1),
        "sync",
        Arc::new(StubSyncStorage::healthy()),
        broker,
    ))
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut sender_socket, _) = connect_async(request.clone())
        .await
        .expect("connect websocket sender");
    let (mut watcher_socket, _) = connect_async(request)
        .await
        .expect("connect websocket watcher");
    let space_id = test_personal_space_id();

    send_auth(&mut sender_socket).await;
    send_auth(&mut watcher_socket).await;
    subscribe_socket_to_space(&mut sender_socket, "sub-presence-sender-5", &space_id).await;
    subscribe_socket_to_space(&mut watcher_socket, "sub-presence-watcher-5", &space_id).await;

    send_binary_frame(
        &mut sender_socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_NOTIFICATION,
            "method": "presence.set",
            "params": {
                "space": space_id,
                "data": vec![7; super::presence::MAX_PRESENCE_DATA_BYTES + 1]
            }
        }),
    )
    .await;

    let watcher_frame =
        tokio::time::timeout(Duration::from_millis(300), watcher_socket.next()).await;
    assert!(
        watcher_frame.is_err(),
        "watcher should not receive oversized presence notification"
    );

    server.handle.abort();
}

#[tokio::test]
async fn websocket_event_send_oversized_payload_is_ignored() {
    let broker = Arc::new(MultiBroker::new(BrokerConfig::default()));
    let server = spawn_server(base_state_with_ws_storage_and_broker(
        Duration::from_secs(1),
        "sync",
        Arc::new(StubSyncStorage::healthy()),
        broker,
    ))
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut sender_socket, _) = connect_async(request.clone())
        .await
        .expect("connect websocket sender");
    let (mut watcher_socket, _) = connect_async(request)
        .await
        .expect("connect websocket watcher");
    let space_id = test_personal_space_id();

    send_auth(&mut sender_socket).await;
    send_auth(&mut watcher_socket).await;
    subscribe_socket_to_space(&mut sender_socket, "sub-event-sender-2", &space_id).await;
    subscribe_socket_to_space(&mut watcher_socket, "sub-event-watcher-2", &space_id).await;

    send_binary_frame(
        &mut sender_socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_NOTIFICATION,
            "method": "event.send",
            "params": {
                "space": space_id,
                "data": vec![7; super::presence::MAX_EVENT_DATA_BYTES + 1]
            }
        }),
    )
    .await;

    let watcher_frame =
        tokio::time::timeout(Duration::from_millis(300), watcher_socket.next()).await;
    assert!(
        watcher_frame.is_err(),
        "watcher should not receive oversized event notification"
    );

    server.handle.abort();
}

#[tokio::test]
async fn websocket_connection_limit_closes_after_auth() {
    let broker = Arc::new(MultiBroker::new(BrokerConfig {
        max_connections_per_mailbox: 1,
    }));
    let server = spawn_server(base_state_with_ws_and_broker(
        Duration::from_secs(1),
        "sync",
        broker,
    ))
    .await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut first_socket, _) = connect_async(request.clone())
        .await
        .expect("connect first websocket");
    send_auth(&mut first_socket).await;

    let (mut second_socket, _) = connect_async(request)
        .await
        .expect("connect second websocket");
    send_auth(&mut second_socket).await;

    let close_code = expect_close_code(&mut second_socket).await;
    assert_eq!(
        close_code,
        less_sync_core::protocol::CLOSE_TOO_MANY_CONNECTIONS as u16
    );

    server.handle.abort();
}

#[tokio::test]
async fn websocket_request_with_empty_id_gets_response() {
    let server = spawn_server(base_state_with_ws(Duration::from_secs(1), "sync")).await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");

    send_auth(&mut socket).await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "method": "nonexistent.method",
            "params": {}
        }),
    )
    .await;

    let response = read_error_response(&mut socket).await;
    assert_eq!(response.id, "");
    assert_eq!(
        response.error.code,
        less_sync_core::protocol::ERR_CODE_METHOD_NOT_FOUND
    );

    server.handle.abort();
}

#[tokio::test]
async fn websocket_unknown_frame_type_does_not_close_connection() {
    let server = spawn_server(base_state_with_ws(Duration::from_secs(1), "sync")).await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");

    send_auth(&mut socket).await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": 99,
            "id": "unk-1",
            "method": "noop"
        }),
    )
    .await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "req-2",
            "method": "nonexistent.method",
            "params": {}
        }),
    )
    .await;

    let response = read_error_response(&mut socket).await;
    assert_eq!(response.id, "req-2");

    server.handle.abort();
}

#[tokio::test]
async fn websocket_unknown_notification_is_ignored() {
    let server = spawn_server(base_state_with_ws(Duration::from_secs(1), "sync")).await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");

    send_auth(&mut socket).await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_NOTIFICATION,
            "method": "some.unknown.event",
            "params": {"foo": "bar"}
        }),
    )
    .await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "req-3",
            "method": "nonexistent.method",
            "params": {}
        }),
    )
    .await;

    let response = read_error_response(&mut socket).await;
    assert_eq!(response.id, "req-3");

    server.handle.abort();
}

#[tokio::test]
async fn websocket_client_response_frame_is_ignored() {
    let server = spawn_server(base_state_with_ws(Duration::from_secs(1), "sync")).await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");

    send_auth(&mut socket).await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_RESPONSE,
            "id": "fake-resp-1",
            "result": {"ok": true}
        }),
    )
    .await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "req-4",
            "method": "nonexistent.method",
            "params": {}
        }),
    )
    .await;

    let response = read_error_response(&mut socket).await;
    assert_eq!(response.id, "req-4");

    server.handle.abort();
}

#[tokio::test]
async fn websocket_client_chunk_frame_is_ignored() {
    let server = spawn_server(base_state_with_ws(Duration::from_secs(1), "sync")).await;
    let request = ws_request(server.addr, Some(less_sync_realtime::ws::WS_SUBPROTOCOL));
    let (mut socket, _) = connect_async(request).await.expect("connect websocket");

    send_auth(&mut socket).await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_CHUNK,
            "id": "fake-chunk-1",
            "name": "pull.record",
            "data": {"id": "r1"}
        }),
    )
    .await;
    send_binary_frame(
        &mut socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": "req-5",
            "method": "nonexistent.method",
            "params": {}
        }),
    )
    .await;

    let response = read_error_response(&mut socket).await;
    assert_eq!(response.id, "req-5");

    server.handle.abort();
}

struct TestServer {
    addr: SocketAddr,
    handle: JoinHandle<()>,
}

async fn spawn_server(state: ApiState) -> TestServer {
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve app");
    });
    TestServer { addr, handle }
}

fn base_state_with_ws(auth_timeout: Duration, scope: &'static str) -> ApiState {
    base_state_with_ws_validator(auth_timeout, Arc::new(StubValidator::with_scope(scope)))
}

fn base_state_with_ws_validator(
    auth_timeout: Duration,
    validator: Arc<dyn TokenValidator + Send + Sync>,
) -> ApiState {
    ApiState::new(Arc::new(StubHealth)).with_websocket_timeout(validator, auth_timeout)
}

fn test_auth_context(scope: &str) -> AuthContext {
    AuthContext {
        issuer: "https://accounts.less.so".to_owned(),
        user_id: "user-1".to_owned(),
        client_id: "client-1".to_owned(),
        personal_space_id: test_personal_space_id(),
        did: "did:key:zDnaStub".to_owned(),
        mailbox_id: "mailbox-1".to_owned(),
        scope: scope.to_owned(),
    }
}

fn test_personal_space_id() -> String {
    "cf78fa75-e714-5073-8972-126a66255b39".to_owned()
}

fn test_personal_space_uuid() -> Uuid {
    Uuid::parse_str("cf78fa75-e714-5073-8972-126a66255b39").expect("valid personal test UUID")
}

fn base_state_with_ws_and_storage(
    auth_timeout: Duration,
    scope: &'static str,
    storage: Arc<dyn SyncStorage>,
) -> ApiState {
    base_state_with_ws(auth_timeout, scope).with_sync_storage_adapter(storage)
}

fn base_state_with_ws_and_broker(
    auth_timeout: Duration,
    scope: &'static str,
    broker: Arc<MultiBroker>,
) -> ApiState {
    base_state_with_ws(auth_timeout, scope).with_realtime_broker(broker)
}

fn base_state_with_ws_storage_and_broker(
    auth_timeout: Duration,
    scope: &'static str,
    storage: Arc<dyn SyncStorage>,
    broker: Arc<MultiBroker>,
) -> ApiState {
    base_state_with_ws(auth_timeout, scope)
        .with_realtime_broker(broker)
        .with_sync_storage_adapter(storage)
}

fn ws_request(addr: SocketAddr, subprotocol: Option<&str>) -> http::Request<()> {
    let mut request = format!("ws://{addr}/api/v1/ws")
        .into_client_request()
        .expect("request");
    if let Some(subprotocol) = subprotocol {
        request.headers_mut().insert(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_str(subprotocol).expect("valid protocol header"),
        );
    }
    request
}

fn assert_http_status(error: WsError, status: StatusCode) {
    match error {
        WsError::Http(response) => assert_eq!(response.status(), status),
        other => panic!("expected HTTP error, got {other:?}"),
    }
}

async fn send_auth(socket: &mut TestSocket) {
    send_auth_with_token(socket, "valid-token").await;
}

async fn send_auth_with_token(socket: &mut TestSocket, token: &str) {
    let frame = serde_cbor::to_vec(&serde_json::json!({
        "type": less_sync_core::protocol::RPC_NOTIFICATION,
        "method": "auth",
        "params": { "token": token }
    }))
    .expect("encode auth frame");
    socket
        .send(WsMessage::Binary(frame.into()))
        .await
        .expect("send auth frame");
}

async fn send_binary_frame(socket: &mut TestSocket, frame: serde_json::Value) {
    let encoded = serde_cbor::to_vec(&frame).expect("encode frame");
    socket
        .send(WsMessage::Binary(encoded.into()))
        .await
        .expect("send frame");
}

async fn subscribe_socket_to_space(socket: &mut TestSocket, request_id: &str, space_id: &str) {
    send_binary_frame(
        socket,
        serde_json::json!({
            "type": less_sync_core::protocol::RPC_REQUEST,
            "id": request_id,
            "method": "subscribe",
            "params": {
                "spaces": [{ "id": space_id, "since": 0 }]
            }
        }),
    )
    .await;

    let response: RpcResultResponse<less_sync_core::protocol::SubscribeResult> =
        read_result_response(socket).await;
    assert_eq!(response.id, request_id);
    assert_eq!(response.result.spaces.len(), 1);
    assert!(response.result.errors.is_empty());
}

async fn expect_close_code(socket: &mut TestSocket) -> u16 {
    let frame = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .expect("read timeout")
        .expect("close frame")
        .expect("websocket read");

    match frame {
        WsMessage::Close(Some(close)) => u16::from(close.code),
        other => panic!("expected close frame, got {other:?}"),
    }
}

#[derive(Debug, Deserialize)]
struct RpcErrorResponse {
    #[serde(rename = "type")]
    frame_type: i32,
    #[serde(rename = "id", default)]
    id: String,
    #[serde(rename = "error")]
    error: RpcErrorPayload,
}

#[derive(Debug, Deserialize)]
struct RpcResultResponse<T> {
    #[serde(rename = "type")]
    _frame_type: i32,
    #[serde(rename = "id", default)]
    id: String,
    #[serde(rename = "result")]
    result: T,
}

#[derive(Debug, Deserialize)]
struct RpcChunkResponse<T> {
    #[serde(rename = "type")]
    _frame_type: i32,
    #[serde(rename = "id", default)]
    id: String,
    #[serde(rename = "name")]
    name: String,
    #[serde(rename = "data")]
    data: T,
}

#[derive(Debug, Deserialize)]
struct RpcNotificationResponse<T> {
    #[serde(rename = "type")]
    _frame_type: i32,
    #[serde(rename = "method")]
    method: String,
    #[serde(rename = "params")]
    params: T,
}

#[derive(Debug, Deserialize)]
struct PullSummaryResult {
    #[serde(rename = "_chunks")]
    chunks: i32,
}

#[derive(Debug, Deserialize)]
struct RpcErrorPayload {
    #[serde(rename = "code")]
    code: String,
    #[serde(rename = "message")]
    _message: String,
}

async fn read_error_response(socket: &mut TestSocket) -> RpcErrorResponse {
    let frame = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .expect("read timeout")
        .expect("response frame")
        .expect("websocket read");

    match frame {
        WsMessage::Binary(data) => serde_cbor::from_slice(&data).expect("decode response"),
        other => panic!("expected binary response frame, got {other:?}"),
    }
}

async fn read_result_response<T>(socket: &mut TestSocket) -> RpcResultResponse<T>
where
    T: for<'de> Deserialize<'de>,
{
    let frame = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .expect("read timeout")
        .expect("response frame")
        .expect("websocket read");

    match frame {
        WsMessage::Binary(data) => serde_cbor::from_slice(&data).expect("decode response"),
        other => panic!("expected binary response frame, got {other:?}"),
    }
}

async fn read_chunk_response<T>(socket: &mut TestSocket) -> RpcChunkResponse<T>
where
    T: for<'de> Deserialize<'de>,
{
    let frame = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .expect("read timeout")
        .expect("chunk frame")
        .expect("websocket read");

    match frame {
        WsMessage::Binary(data) => serde_cbor::from_slice(&data).expect("decode chunk"),
        other => panic!("expected binary chunk frame, got {other:?}"),
    }
}

async fn read_notification_response<T>(socket: &mut TestSocket) -> RpcNotificationResponse<T>
where
    T: for<'de> Deserialize<'de>,
{
    let frame = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .expect("read timeout")
        .expect("notification frame")
        .expect("websocket read");

    match frame {
        WsMessage::Binary(data) => serde_cbor::from_slice(&data).expect("decode notification"),
        other => panic!("expected binary notification frame, got {other:?}"),
    }
}
