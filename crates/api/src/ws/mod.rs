use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::header::SEC_WEBSOCKET_PROTOCOL;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use less_sync_realtime::ws::{
    authenticate_first_message, parse_client_binary_frame, ClientFrame, CloseDirective,
    FirstMessage, WS_SUBPROTOCOL,
};
use uuid::Uuid;

use crate::ApiState;

mod authz;
mod realtime;
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
    let realtime_broker = state.realtime_broker();

    ws.protocols([WS_SUBPROTOCOL])
        .on_upgrade(move |socket| serve_websocket(socket, config, sync_storage, realtime_broker))
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
    socket: WebSocket,
    config: crate::WebSocketState,
    sync_storage: Option<Arc<dyn SyncStorage>>,
    realtime_broker: Option<Arc<less_sync_realtime::broker::MultiBroker>>,
) {
    let (mut socket_sender, mut socket_receiver) = socket.split();
    let (outbound, mut outbound_rx) = realtime::outbound_channel();
    let closed = Arc::new(AtomicBool::new(false));
    let writer_closed = Arc::clone(&closed);

    let writer = tokio::spawn(async move {
        while let Some(frame) = outbound_rx.recv().await {
            match frame {
                realtime::OutboundFrame::Binary(payload) => {
                    if socket_sender
                        .send(Message::Binary(payload.to_vec().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                realtime::OutboundFrame::Close(close) => {
                    let frame = CloseFrame {
                        code: close.code as u16,
                        reason: close.reason.into(),
                    };
                    let _ = socket_sender.send(Message::Close(Some(frame))).await;
                    break;
                }
            }
        }
        writer_closed.store(true, Ordering::Relaxed);
    });

    let first_message =
        match tokio::time::timeout(config.auth_timeout, socket_receiver.next()).await {
            Ok(Some(Ok(message))) => to_first_message(message),
            Ok(Some(Err(_))) => {
                realtime::send_close(
                    &outbound,
                    CloseDirective::auth_failed("failed to read auth frame"),
                )
                .await;
                drop(outbound);
                let _ = writer.await;
                return;
            }
            Ok(None) => {
                realtime::send_close(
                    &outbound,
                    CloseDirective::auth_failed("connection closed before auth"),
                )
                .await;
                drop(outbound);
                let _ = writer.await;
                return;
            }
            Err(_) => {
                realtime::send_close(&outbound, CloseDirective::auth_failed("auth timeout")).await;
                drop(outbound);
                let _ = writer.await;
                return;
            }
        };

    let auth_context =
        match authenticate_first_message(config.validator.as_ref(), first_message).await {
            Ok(context) => context,
            Err(error) => {
                realtime::send_close(&outbound, error.close).await;
                drop(outbound);
                let _ = writer.await;
                return;
            }
        };

    let connection_id = Uuid::new_v4().to_string();
    let realtime_session = match realtime::register_session(
        realtime_broker,
        &auth_context,
        &connection_id,
        outbound.clone(),
        Arc::clone(&closed),
    )
    .await
    {
        Ok(session) => session,
        Err(close) => {
            realtime::send_close(&outbound, close).await;
            drop(outbound);
            let _ = writer.await;
            return;
        }
    };

    while let Some(message) = socket_receiver.next().await {
        let message = match message {
            Ok(message) => message,
            Err(_) => break,
        };

        match message {
            Message::Binary(payload) => match parse_client_binary_frame(&payload) {
                Ok(ClientFrame::Request { id, method }) => {
                    rpc::handle_request(
                        &outbound,
                        sync_storage.as_deref(),
                        realtime_session.as_ref(),
                        &auth_context,
                        &id,
                        &method,
                        &payload,
                    )
                    .await;
                }
                Ok(ClientFrame::Notification { method }) => {
                    rpc::handle_notification(realtime_session.as_ref(), &method, &payload).await;
                }
                Ok(
                    ClientFrame::Keepalive
                    | ClientFrame::Response
                    | ClientFrame::Chunk
                    | ClientFrame::UnknownType,
                ) => {}
                Err(close) => {
                    realtime::send_close(&outbound, close).await;
                    break;
                }
            },
            Message::Text(_) => {
                realtime::send_close(
                    &outbound,
                    CloseDirective::protocol_error("expected binary rpc frame"),
                )
                .await;
                break;
            }
            Message::Close(_) => break,
            Message::Ping(_) | Message::Pong(_) => {}
        }
    }

    if let Some(session) = realtime_session.as_ref() {
        session.unregister().await;
    }
    closed.store(true, Ordering::Relaxed);
    drop(outbound);
    let _ = writer.await;
}

fn to_first_message(message: Message) -> FirstMessage {
    match message {
        Message::Binary(payload) => FirstMessage::Binary(payload.to_vec()),
        Message::Close(_) => FirstMessage::Closed,
        Message::Text(_) | Message::Ping(_) | Message::Pong(_) => FirstMessage::NonBinary,
    }
}

#[cfg(test)]
mod tests;
