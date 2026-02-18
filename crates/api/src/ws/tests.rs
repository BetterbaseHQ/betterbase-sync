use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use http::header::SEC_WEBSOCKET_PROTOCOL;
use http::{HeaderValue, StatusCode};
use less_sync_auth::{AuthContext, AuthError, TokenValidator};
use serde::Deserialize;
use tokio::task::JoinHandle;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{Error as WsError, Message as WsMessage};

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
    scope: &'static str,
}

#[async_trait]
impl TokenValidator for StubValidator {
    async fn validate_token(&self, token: &str) -> Result<AuthContext, AuthError> {
        if token != "valid-token" {
            return Err(AuthError::InvalidToken);
        }
        Ok(AuthContext {
            user_id: "user-1".to_owned(),
            client_id: "client-1".to_owned(),
            scope: self.scope.to_owned(),
        })
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
    ApiState::new(Arc::new(StubHealth))
        .with_websocket_timeout(Arc::new(StubValidator { scope }), auth_timeout)
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
    let frame = serde_cbor::to_vec(&serde_json::json!({
        "type": less_sync_core::protocol::RPC_NOTIFICATION,
        "method": "auth",
        "params": { "token": "valid-token" }
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
