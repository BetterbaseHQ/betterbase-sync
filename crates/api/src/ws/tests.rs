use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use http::header::SEC_WEBSOCKET_PROTOCOL;
use http::{HeaderValue, StatusCode};
use less_sync_auth::{AuthContext, AuthError, TokenValidator};
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
