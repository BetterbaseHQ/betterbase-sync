use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::header::SEC_WEBSOCKET_PROTOCOL;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use less_sync_auth::AuthContext;
use less_sync_core::protocol::{
    SubscribeParams, SubscribeResult, WsSpaceError, WsSubscribedSpace, ERR_CODE_BAD_REQUEST,
    ERR_CODE_INTERNAL, ERR_CODE_METHOD_NOT_FOUND, RPC_RESPONSE,
};
use less_sync_realtime::ws::{
    authenticate_first_message, parse_client_binary_frame, ClientFrame, CloseDirective,
    FirstMessage, WS_SUBPROTOCOL,
};
use less_sync_storage::{Storage, StorageError};
use serde::de::DeserializeOwned;
use serde::Serialize;
use uuid::Uuid;

use crate::ApiState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SubscribedSpaceState {
    pub cursor: i64,
    pub key_generation: i32,
    pub rewrap_epoch: Option<i32>,
}

#[async_trait]
pub(crate) trait SyncStorage: Send + Sync {
    async fn get_or_create_space(
        &self,
        space_id: Uuid,
        client_id: &str,
    ) -> Result<SubscribedSpaceState, StorageError>;
}

#[async_trait]
impl<T> SyncStorage for T
where
    T: Storage + Send + Sync,
{
    async fn get_or_create_space(
        &self,
        space_id: Uuid,
        client_id: &str,
    ) -> Result<SubscribedSpaceState, StorageError> {
        let space = Storage::get_or_create_space(self, space_id, client_id).await?;
        Ok(SubscribedSpaceState {
            cursor: space.cursor,
            key_generation: space.key_generation,
            rewrap_epoch: space.rewrap_epoch,
        })
    }
}

pub(crate) async fn websocket_upgrade(
    State(state): State<ApiState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !requested_subprotocol(&headers) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let Some(config) = state.websocket() else {
        return StatusCode::NOT_IMPLEMENTED.into_response();
    };
    let sync_storage = state.sync_storage();

    ws.protocols([WS_SUBPROTOCOL])
        .on_upgrade(move |socket| serve_websocket(socket, config, sync_storage))
        .into_response()
}

fn requested_subprotocol(headers: &HeaderMap) -> bool {
    headers
        .get(SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .map(str::trim)
                .any(|candidate| candidate == WS_SUBPROTOCOL)
        })
}

async fn serve_websocket(
    mut socket: WebSocket,
    config: crate::WebSocketState,
    sync_storage: Option<Arc<dyn SyncStorage>>,
) {
    let first_message = match tokio::time::timeout(config.auth_timeout, socket.next()).await {
        Ok(Some(Ok(message))) => to_first_message(message),
        Ok(Some(Err(_))) => {
            send_close(
                &mut socket,
                CloseDirective::auth_failed("failed to read auth frame"),
            )
            .await;
            return;
        }
        Ok(None) => {
            send_close(
                &mut socket,
                CloseDirective::auth_failed("connection closed before auth"),
            )
            .await;
            return;
        }
        Err(_) => {
            send_close(&mut socket, CloseDirective::auth_failed("auth timeout")).await;
            return;
        }
    };

    let auth_context =
        match authenticate_first_message(config.validator.as_ref(), first_message).await {
            Ok(context) => context,
            Err(error) => {
                send_close(&mut socket, error.close).await;
                return;
            }
        };

    while let Some(message) = socket.next().await {
        let message = match message {
            Ok(message) => message,
            Err(_) => return,
        };

        match message {
            Message::Binary(payload) => match parse_client_binary_frame(&payload) {
                Ok(ClientFrame::Request { id, method }) => {
                    handle_request(
                        &mut socket,
                        sync_storage.as_deref(),
                        &auth_context,
                        &id,
                        &method,
                        &payload,
                    )
                    .await;
                }
                Ok(
                    ClientFrame::Keepalive
                    | ClientFrame::Notification { .. }
                    | ClientFrame::Response
                    | ClientFrame::Chunk
                    | ClientFrame::UnknownType,
                ) => {}
                Err(close) => {
                    send_close(&mut socket, close).await;
                    return;
                }
            },
            Message::Text(_) => {
                send_close(
                    &mut socket,
                    CloseDirective::protocol_error("expected binary rpc frame"),
                )
                .await;
                return;
            }
            Message::Close(_) => return,
            Message::Ping(_) | Message::Pong(_) => {}
        }
    }
}

async fn handle_request(
    socket: &mut WebSocket,
    sync_storage: Option<&dyn SyncStorage>,
    auth: &AuthContext,
    id: &str,
    method: &str,
    payload: &[u8],
) {
    match method {
        "subscribe" => {
            let Some(sync_storage) = sync_storage else {
                send_error_response(
                    socket,
                    id,
                    ERR_CODE_INTERNAL,
                    "sync storage is not configured".to_owned(),
                )
                .await;
                return;
            };
            handle_subscribe_request(socket, sync_storage, auth, id, payload).await;
        }
        _ => {
            send_method_not_found_response(socket, id, method).await;
        }
    }
}

async fn handle_subscribe_request(
    socket: &mut WebSocket,
    sync_storage: &dyn SyncStorage,
    auth: &AuthContext,
    id: &str,
    payload: &[u8],
) {
    let params = match decode_request_params::<SubscribeParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                socket,
                id,
                ERR_CODE_BAD_REQUEST,
                "invalid subscribe params".to_owned(),
            )
            .await;
            return;
        }
    };

    let mut spaces = Vec::with_capacity(params.spaces.len());
    let mut errors = Vec::new();
    for requested in &params.spaces {
        let space_id = match Uuid::parse_str(&requested.id) {
            Ok(space_id) => space_id,
            Err(_) => {
                errors.push(WsSpaceError {
                    space: requested.id.clone(),
                    error: ERR_CODE_BAD_REQUEST.to_owned(),
                });
                continue;
            }
        };

        match sync_storage
            .get_or_create_space(space_id, &auth.client_id)
            .await
        {
            Ok(space) => spaces.push(WsSubscribedSpace {
                id: requested.id.clone(),
                cursor: space.cursor,
                key_generation: space.key_generation,
                rewrap_epoch: space.rewrap_epoch,
                token: String::new(),
                peers: Vec::new(),
            }),
            Err(_) => errors.push(WsSpaceError {
                space: requested.id.clone(),
                error: ERR_CODE_INTERNAL.to_owned(),
            }),
        }
    }

    send_result_response(socket, id, &SubscribeResult { spaces, errors }).await;
}

fn decode_request_params<T>(payload: &[u8]) -> Result<T, serde_cbor::Error>
where
    T: DeserializeOwned,
{
    #[derive(serde::Deserialize)]
    struct RequestEnvelope<T> {
        #[serde(rename = "params")]
        params: T,
    }

    serde_cbor::from_slice::<RequestEnvelope<T>>(payload).map(|envelope| envelope.params)
}

fn to_first_message(message: Message) -> FirstMessage {
    match message {
        Message::Binary(payload) => FirstMessage::Binary(payload.to_vec()),
        Message::Close(_) => FirstMessage::Closed,
        Message::Text(_) | Message::Ping(_) | Message::Pong(_) => FirstMessage::NonBinary,
    }
}

async fn send_close(socket: &mut WebSocket, close: CloseDirective) {
    let frame = CloseFrame {
        code: close.code as u16,
        reason: close.reason.into(),
    };
    let _ = socket.send(Message::Close(Some(frame))).await;
}

#[derive(Debug, Serialize)]
struct RpcErrorFrame<'a> {
    #[serde(rename = "type")]
    frame_type: i32,
    #[serde(rename = "id")]
    id: &'a str,
    #[serde(rename = "error")]
    error: RpcErrorPayload,
}

#[derive(Debug, Serialize)]
struct RpcErrorPayload {
    #[serde(rename = "code")]
    code: &'static str,
    #[serde(rename = "message")]
    message: String,
}

#[derive(Debug, Serialize)]
struct RpcResultFrame<'a, T>
where
    T: Serialize,
{
    #[serde(rename = "type")]
    frame_type: i32,
    #[serde(rename = "id")]
    id: &'a str,
    #[serde(rename = "result")]
    result: &'a T,
}

async fn send_method_not_found_response(socket: &mut WebSocket, id: &str, method: &str) {
    send_error_response(
        socket,
        id,
        ERR_CODE_METHOD_NOT_FOUND,
        format!("unknown method: {method}"),
    )
    .await;
}

async fn send_result_response<T>(socket: &mut WebSocket, id: &str, result: &T)
where
    T: Serialize,
{
    let frame = RpcResultFrame {
        frame_type: RPC_RESPONSE,
        id,
        result,
    };
    let encoded = match serde_cbor::to_vec(&frame) {
        Ok(encoded) => encoded,
        Err(_) => return,
    };
    let _ = socket.send(Message::Binary(encoded.into())).await;
}

async fn send_error_response(
    socket: &mut WebSocket,
    id: &str,
    code: &'static str,
    message: String,
) {
    let frame = RpcErrorFrame {
        frame_type: RPC_RESPONSE,
        id,
        error: RpcErrorPayload { code, message },
    };
    let encoded = match serde_cbor::to_vec(&frame) {
        Ok(encoded) => encoded,
        Err(_) => return,
    };
    let _ = socket.send(Message::Binary(encoded.into())).await;
}

#[cfg(test)]
mod tests;
