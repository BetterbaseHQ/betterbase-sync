use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{OriginalUri, State};
use axum::http::header::SEC_WEBSOCKET_PROTOCOL;
use axum::http::{HeaderMap, Method, Request, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use less_sync_auth::AuthContext;
use less_sync_core::protocol::CLOSE_TOO_MANY_CONNECTIONS;
use less_sync_realtime::ws::{
    authenticate_first_message, parse_client_binary_frame, ClientFrame, CloseDirective,
    FirstMessage, WS_SUBPROTOCOL,
};
use uuid::Uuid;

use crate::ApiState;

mod authz;
mod presence;
mod realtime;
mod rpc;
mod storage;

pub(crate) use presence::PresenceRegistry;
pub(crate) use storage::SyncStorage;

#[derive(Clone)]
enum ConnectionMode {
    Client,
    Federation { peer_domain: String },
}

#[derive(Clone)]
struct WebSocketRuntimeContext {
    sync_storage: Option<Arc<dyn SyncStorage>>,
    realtime_broker: Option<Arc<less_sync_realtime::broker::MultiBroker>>,
    presence_registry: Option<Arc<PresenceRegistry>>,
    connection_mode: ConnectionMode,
    federation_token_keys: Option<crate::FederationTokenKeys>,
    federation_quota_tracker: Arc<crate::FederationQuotaTracker>,
}

pub(crate) async fn websocket_upgrade(
    State(state): State<ApiState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    websocket_upgrade_with_mode(state, headers, ws).await
}

pub(crate) async fn federation_websocket_upgrade(
    State(state): State<ApiState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !requested_subprotocol(&headers) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let Some(config) = state.websocket() else {
        return StatusCode::NOT_IMPLEMENTED.into_response();
    };
    let Some(federation_authenticator) = state.federation_authenticator() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let auth_request = build_federation_auth_request(&uri, &headers);
    let auth_context = match federation_authenticator.authenticate_request(&auth_request) {
        Ok(context) => context,
        Err(error) => return (error.status, error.message).into_response(),
    };
    let Some(peer_domain) =
        crate::federation::federation_peer_domain(&auth_context).map(ToOwned::to_owned)
    else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid federation auth context",
        )
            .into_response();
    };

    let runtime_context = WebSocketRuntimeContext {
        sync_storage: state.sync_storage(),
        realtime_broker: state.realtime_broker(),
        presence_registry: state.presence_registry(),
        connection_mode: ConnectionMode::Federation { peer_domain },
        federation_token_keys: state.federation_token_keys(),
        federation_quota_tracker: state.federation_quota_tracker(),
    };
    ws.protocols([WS_SUBPROTOCOL])
        .on_upgrade(move |socket| {
            serve_websocket(socket, config, Some(auth_context), runtime_context)
        })
        .into_response()
}

async fn websocket_upgrade_with_mode(
    state: ApiState,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !requested_subprotocol(&headers) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let Some(config) = state.websocket() else {
        return StatusCode::NOT_IMPLEMENTED.into_response();
    };
    let runtime_context = WebSocketRuntimeContext {
        sync_storage: state.sync_storage(),
        realtime_broker: state.realtime_broker(),
        presence_registry: state.presence_registry(),
        connection_mode: ConnectionMode::Client,
        federation_token_keys: state.federation_token_keys(),
        federation_quota_tracker: state.federation_quota_tracker(),
    };

    ws.protocols([WS_SUBPROTOCOL])
        .on_upgrade(move |socket| serve_websocket(socket, config, None, runtime_context))
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

fn build_federation_auth_request(uri: &Uri, headers: &HeaderMap) -> Request<()> {
    let request_uri = if uri.scheme().is_some() && uri.authority().is_some() {
        uri.to_string()
    } else if let Some(host) = headers.get("host").and_then(|value| value.to_str().ok()) {
        format!("ws://{host}{uri}")
    } else {
        uri.to_string()
    };

    let mut request = Request::builder()
        .method(Method::GET)
        .uri(request_uri)
        .body(())
        .expect("federation auth request should be constructible");
    *request.headers_mut() = headers.clone();
    request
}

async fn serve_websocket(
    socket: WebSocket,
    config: crate::WebSocketState,
    initial_auth_context: Option<AuthContext>,
    runtime_context: WebSocketRuntimeContext,
) {
    let mut socket = socket;
    let federation_connection_tracked =
        if let ConnectionMode::Federation { peer_domain } = &runtime_context.connection_mode {
            if runtime_context
                .federation_quota_tracker
                .try_add_connection(peer_domain)
                .await
            {
                true
            } else {
                let _ = socket
                    .send(Message::Close(Some(CloseFrame {
                        code: CLOSE_TOO_MANY_CONNECTIONS as u16,
                        reason: "too many federation connections".into(),
                    })))
                    .await;
                return;
            }
        } else {
            false
        };

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

    let mut auth_context = if let Some(context) = initial_auth_context {
        context
    } else {
        let first_message = match tokio::time::timeout(config.auth_timeout, socket_receiver.next())
            .await
        {
            Ok(Some(Ok(message))) => to_first_message(message),
            Ok(Some(Err(_))) => {
                realtime::send_close(
                    &outbound,
                    CloseDirective::auth_failed("failed to read auth frame"),
                )
                .await;
                drop(outbound);
                let _ = writer.await;
                if federation_connection_tracked {
                    release_federation_quotas(&runtime_context, None).await;
                }
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
                if federation_connection_tracked {
                    release_federation_quotas(&runtime_context, None).await;
                }
                return;
            }
            Err(_) => {
                realtime::send_close(&outbound, CloseDirective::auth_failed("auth timeout")).await;
                drop(outbound);
                let _ = writer.await;
                if federation_connection_tracked {
                    release_federation_quotas(&runtime_context, None).await;
                }
                return;
            }
        };

        match authenticate_first_message(config.validator.as_ref(), first_message).await {
            Ok(context) => context,
            Err(error) => {
                realtime::send_close(&outbound, error.close).await;
                drop(outbound);
                let _ = writer.await;
                if federation_connection_tracked {
                    release_federation_quotas(&runtime_context, None).await;
                }
                return;
            }
        }
    };

    let connection_id = Uuid::new_v4().to_string();
    let realtime_session = match realtime::register_session(
        runtime_context.realtime_broker.clone(),
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
            if federation_connection_tracked {
                release_federation_quotas(&runtime_context, None).await;
            }
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
                    let request_mode = match &runtime_context.connection_mode {
                        ConnectionMode::Client => rpc::RequestMode::Client,
                        ConnectionMode::Federation { peer_domain } => {
                            rpc::RequestMode::Federation {
                                peer_domain,
                                token_keys: runtime_context.federation_token_keys.as_ref(),
                                quota_tracker: Some(
                                    runtime_context.federation_quota_tracker.as_ref(),
                                ),
                            }
                        }
                    };
                    rpc::handle_request(
                        &outbound,
                        rpc::RequestContext {
                            sync_storage: runtime_context.sync_storage.as_deref(),
                            realtime: realtime_session.as_ref(),
                            presence_registry: runtime_context.presence_registry.as_deref(),
                        },
                        request_mode,
                        &mut auth_context,
                        config.validator.as_ref(),
                        rpc::RequestFrame {
                            id: &id,
                            method: &method,
                            payload: &payload,
                        },
                    )
                    .await;
                }
                Ok(ClientFrame::Notification { method }) => {
                    let request_mode = match &runtime_context.connection_mode {
                        ConnectionMode::Client => rpc::RequestMode::Client,
                        ConnectionMode::Federation { peer_domain } => {
                            rpc::RequestMode::Federation {
                                peer_domain,
                                token_keys: runtime_context.federation_token_keys.as_ref(),
                                quota_tracker: Some(
                                    runtime_context.federation_quota_tracker.as_ref(),
                                ),
                            }
                        }
                    };
                    rpc::handle_notification(
                        request_mode,
                        realtime_session.as_ref(),
                        runtime_context.presence_registry.as_deref(),
                        &method,
                        &payload,
                    )
                    .await;
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
        if let Some(presence_registry) = runtime_context.presence_registry.as_deref() {
            let cleared_spaces = presence_registry.clear_peer(session.peer_id()).await;
            for space_id in &cleared_spaces {
                session
                    .broadcast_presence_leave(space_id, session.peer_id())
                    .await;
            }
        }
        session.unregister().await;
    }
    if federation_connection_tracked {
        release_federation_quotas(&runtime_context, realtime_session.as_ref()).await;
    }
    closed.store(true, Ordering::Relaxed);
    drop(outbound);
    let _ = writer.await;
}

async fn release_federation_quotas(
    runtime_context: &WebSocketRuntimeContext,
    realtime_session: Option<&realtime::RealtimeSession>,
) {
    let ConnectionMode::Federation { peer_domain } = &runtime_context.connection_mode else {
        return;
    };

    if let Some(session) = realtime_session {
        let subscribed = session.subscribed_space_count().await;
        runtime_context
            .federation_quota_tracker
            .remove_spaces(peer_domain, subscribed)
            .await;
    }

    runtime_context
        .federation_quota_tracker
        .remove_connection(peer_domain)
        .await;
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
