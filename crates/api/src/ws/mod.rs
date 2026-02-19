use std::sync::Arc;

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::header::SEC_WEBSOCKET_PROTOCOL;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use less_sync_realtime::ws::{
    authenticate_first_message, parse_client_binary_frame, ClientFrame, CloseDirective,
    FirstMessage, WS_SUBPROTOCOL,
};

use crate::ApiState;

mod rpc;
mod storage;

pub(crate) use storage::SyncStorage;

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
                    rpc::handle_request(
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

#[cfg(test)]
mod tests;
