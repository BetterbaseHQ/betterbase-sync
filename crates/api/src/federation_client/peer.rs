use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use betterbase_sync_auth::sign_http_request;
use betterbase_sync_realtime::ws::WS_SUBPROTOCOL;
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use http::header::SEC_WEBSOCKET_PROTOCOL;
use http::{HeaderValue, Method, Request};
use std::sync::RwLock;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use url::Url;

use super::wire::{decode_inbound_frame, encode_request_frame, InboundFrame};
use super::{FederationPeerError, PeerNotificationHandler};

type PeerSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;
type PeerSink = futures_util::stream::SplitSink<PeerSocket, Message>;
type PeerStream = futures_util::stream::SplitStream<PeerSocket>;

/// Upper bound for each peer RPC phase: connection setup, write, response
/// streaming, and teardown. A stalled peer must not hold the socket-state
/// mutex or an in-flight call indefinitely (AUD-037).
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq)]
pub(super) struct ReceivedChunk {
    pub(super) name: String,
    pub(super) data: betterbase_sync_core::protocol::CborValue,
}

pub(super) struct PeerConnection {
    ws_url: String,
    response_timeout: Duration,
    subscription_lock: Mutex<()>,
    spaces: Arc<RwLock<HashMap<String, String>>>,
    notifications: PeerNotificationHandler,
    state: Arc<Mutex<PeerState>>,
    reader: std::sync::Mutex<Option<tokio::task::AbortHandle>>,
    closed: AtomicBool,
}

struct PeerState {
    sink: Option<PeerSink>,
    pending: PendingCalls,
    generation: u64,
}

type PendingCalls = Arc<std::sync::Mutex<HashMap<String, Arc<PendingCall>>>>;

// A caller's cancellation must release its response/chunk accumulator without
// spawning cleanup or waiting for the socket-state mutex.
struct PendingRegistration {
    calls: PendingCalls,
    id: String,
}
impl Drop for PendingRegistration {
    fn drop(&mut self) {
        self.calls.lock().expect("pending calls").remove(&self.id);
    }
}

impl Drop for PeerConnection {
    fn drop(&mut self) {
        if let Some(reader) = self.reader.lock().expect("reader task").take() {
            reader.abort();
        }
    }
}

pub(super) struct SubscriptionRegistration {
    spaces: Arc<RwLock<HashMap<String, String>>>,
    previous: HashMap<String, Option<String>>,
    committed: bool,
}
impl SubscriptionRegistration {
    pub(super) fn restore_transient(&self, space: &str) {
        let mut spaces = self.spaces.write().expect("subscription tokens");
        if let Some(Some(token)) = self.previous.get(space) {
            spaces.insert(space.to_owned(), token.clone());
        } else {
            spaces.remove(space);
        }
    }

    pub(super) fn commit(mut self) {
        self.committed = true;
    }
}
impl Drop for SubscriptionRegistration {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let mut spaces = self.spaces.write().expect("subscription tokens");
        for (space, token) in &self.previous {
            if let Some(token) = token {
                spaces.insert(space.clone(), token.clone());
            } else {
                spaces.remove(space);
            }
        }
    }
}

struct PendingCall {
    chunks: std::sync::Mutex<Vec<ReceivedChunk>>,
    outcome: std::sync::Mutex<
        Option<Result<betterbase_sync_core::protocol::CborValue, FederationPeerError>>,
    >,
    done: Notify,
}

impl PendingCall {
    fn new() -> Self {
        Self {
            chunks: std::sync::Mutex::new(Vec::new()),
            outcome: std::sync::Mutex::new(None),
            done: Notify::new(),
        }
    }

    fn push_chunk(&self, chunk: ReceivedChunk) {
        self.chunks
            .lock()
            .expect("lock chunk accumulator")
            .push(chunk);
    }

    fn complete(
        &self,
        outcome: Result<betterbase_sync_core::protocol::CborValue, FederationPeerError>,
    ) {
        *self.outcome.lock().expect("lock outcome") = Some(outcome);
        self.done.notify_waiters();
    }

    fn take(
        &self,
    ) -> Result<
        (
            betterbase_sync_core::protocol::CborValue,
            Vec<ReceivedChunk>,
        ),
        FederationPeerError,
    > {
        let outcome = self
            .outcome
            .lock()
            .expect("lock outcome")
            .take()
            .unwrap_or(Err(FederationPeerError::Closed));
        let chunks = std::mem::take(&mut *self.chunks.lock().expect("lock chunk accumulator"));
        outcome.map(|value| (value, chunks))
    }
}

impl PeerConnection {
    pub(super) fn new(
        _domain: String,
        ws_url: String,
        notifications: PeerNotificationHandler,
    ) -> Self {
        Self {
            ws_url,
            response_timeout: RESPONSE_TIMEOUT,
            subscription_lock: Mutex::new(()),
            spaces: Arc::new(RwLock::new(HashMap::new())),
            notifications,
            state: Arc::new(Mutex::new(PeerState {
                sink: None,
                pending: Arc::new(std::sync::Mutex::new(HashMap::new())),
                generation: 0,
            })),
            reader: std::sync::Mutex::new(None),
            closed: AtomicBool::new(false),
        }
    }

    pub(super) async fn subscription_guard(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.subscription_lock.lock().await
    }
    pub(super) fn prepare_subscription(
        &self,
        ids: impl Iterator<Item = String>,
    ) -> SubscriptionRegistration {
        let mut spaces = self.spaces.write().expect("subscription tokens");
        let mut previous = HashMap::new();
        for id in ids {
            previous
                .entry(id.clone())
                .or_insert_with(|| spaces.get(&id).cloned());
            spaces.entry(id).or_default();
        }
        SubscriptionRegistration {
            spaces: self.spaces.clone(),
            previous,
            committed: false,
        }
    }

    #[cfg(test)]
    pub(super) fn with_response_timeout(mut self, timeout: Duration) -> Self {
        self.response_timeout = timeout;
        self
    }

    #[cfg(test)]
    pub(super) async fn pending_count(&self) -> usize {
        self.state
            .lock()
            .await
            .pending
            .lock()
            .expect("pending calls")
            .len()
    }

    pub(super) async fn call_raw<P>(
        &self,
        key_id: &str,
        signing_key: &SigningKey,
        request_id: &str,
        method: &str,
        params: &P,
    ) -> Result<
        (
            betterbase_sync_core::protocol::CborValue,
            Vec<ReceivedChunk>,
        ),
        FederationPeerError,
    >
    where
        P: serde::Serialize,
    {
        let frame = encode_request_frame(request_id, method, params)?;

        let mut state = self.state.lock().await;
        if self.closed.load(Ordering::Acquire) {
            return Err(FederationPeerError::Closed);
        }
        if state.sink.is_none() {
            match tokio::time::timeout(
                self.response_timeout,
                connect_socket(&self.ws_url, key_id, signing_key),
            )
            .await
            .unwrap_or(Err(FederationPeerError::Closed))
            {
                Ok(socket) => {
                    let (sink, stream) = socket.split();
                    state.generation += 1;
                    let reader = tokio::spawn(read_peer_socket(
                        stream,
                        Arc::clone(&self.state),
                        Arc::clone(&self.spaces),
                        Arc::clone(&self.notifications),
                        state.generation,
                        self.response_timeout,
                    ));
                    if let Some(previous) = self
                        .reader
                        .lock()
                        .expect("reader task")
                        .replace(reader.abort_handle())
                    {
                        previous.abort();
                    }
                    state.sink = Some(sink);
                }
                Err(error) => return Err(error),
            }
        }

        let generation = state.generation;
        let call = Arc::new(PendingCall::new());
        state
            .pending
            .lock()
            .expect("pending calls")
            .insert(request_id.to_owned(), Arc::clone(&call));
        let _registration = PendingRegistration {
            calls: state.pending.clone(),
            id: request_id.to_owned(),
        };

        // Register interest BEFORE sending: `Notify::notify_waiters` wakes
        // only already-registered waiters, so a peer answering within the
        // send/await gap must find a waiter armed. `enable()` arms the
        // future without polling it.
        let mut notified = std::pin::pin!(call.done.notified());
        notified.as_mut().enable();

        // The write is deadline-bounded too: a trusted peer that stops
        // reading (TCP backpressure) would otherwise wedge the send while
        // the state mutex is held, starving the reader and `close()`.
        let send_result = match state.sink.as_mut() {
            Some(sink) => tokio::time::timeout(
                self.response_timeout,
                sink.send(Message::Binary(frame.into())),
            )
            .await
            .ok(),
            None => None,
        };
        let send_failed = !matches!(send_result, Some(Ok(())));
        if send_failed {
            teardown(&mut state, self.response_timeout).await;
            return Err(FederationPeerError::Closed);
        }
        drop(state);

        let wait = tokio::time::timeout(self.response_timeout, notified).await;
        let mut state = self.state.lock().await;
        state
            .pending
            .lock()
            .expect("pending calls")
            .remove(request_id);
        if state.generation != generation {
            return call.take();
        }
        match wait {
            Ok(()) => {
                let result = call.take();
                if matches!(result, Err(FederationPeerError::Closed)) {
                    // The reader reported a fatal condition for this call —
                    // treat the connection as unhealthy.
                    teardown(&mut state, self.response_timeout).await;
                }
                result
            }
            Err(_) => {
                // Deadline elapsed — but the reader may have completed the
                // call in the final instants (lost wakeup / late frame).
                // Prefer a stored outcome over tearing down a healthy
                // connection.
                if let Ok(done) = call.take() {
                    return Ok(done);
                }
                // The peer stalled. Reset the connection so the next call
                // reconnects instead of queuing behind it.
                teardown(&mut state, self.response_timeout).await;
                Err(FederationPeerError::Closed)
            }
        }
    }

    pub(super) async fn set_space_tokens(&self, token_by_space: HashMap<String, String>) {
        let mut spaces = self.spaces.write().expect("subscription tokens");
        for (space, token) in token_by_space {
            spaces.insert(space, token);
        }
    }

    pub(super) async fn remove_space_tokens(&self, space_ids: &[String]) {
        let mut spaces = self.spaces.write().expect("subscription tokens");
        for space_id in space_ids {
            spaces.remove(space_id);
        }
    }

    pub(super) async fn space_tokens(&self) -> HashMap<String, String> {
        self.spaces.read().expect("subscription tokens").clone()
    }

    pub(super) async fn close(&self) {
        self.closed.store(true, Ordering::Release);
        let mut state = self.state.lock().await;
        teardown(&mut state, self.response_timeout).await;
    }
}

/// Fail every in-flight call and drop the socket so the next call
/// reconnects from scratch. The reader task observes the closed stream and
/// exits on its own.
async fn teardown(state: &mut PeerState, timeout: Duration) {
    if let Some(mut sink) = state.sink.take() {
        let _ = tokio::time::timeout(timeout, sink.close()).await;
    }
    let pending = std::mem::take(&mut *state.pending.lock().expect("pending calls"));
    for (_, call) in pending {
        call.complete(Err(FederationPeerError::Closed));
    }
}

/// Dedicated reader for an outgoing peer socket (AUD-037): responses and
/// chunks route to their pending calls while notifications fan out to the
/// local broker instead of being discarded mid-response.
async fn read_peer_socket(
    mut stream: PeerStream,
    state: Arc<Mutex<PeerState>>,
    spaces: Arc<RwLock<HashMap<String, String>>>,
    notifications: PeerNotificationHandler,
    generation: u64,
    timeout: Duration,
) {
    loop {
        let frame = match stream.next().await {
            Some(Ok(frame)) => frame,
            Some(Err(_)) | None => break,
        };
        if state.lock().await.generation != generation {
            return;
        }
        match frame {
            Message::Binary(payload) => {
                if payload.len() == 1 && payload[0] == 0xF6 {
                    continue;
                }

                let decoded = match decode_inbound_frame(payload.as_ref()) {
                    Ok(decoded) => decoded,
                    Err(_) => continue,
                };
                match decoded {
                    InboundFrame::Response(response) => {
                        if response.frame_type != betterbase_sync_core::protocol::RPC_RESPONSE {
                            continue;
                        }
                        let state = state.lock().await;
                        let call = state
                            .pending
                            .lock()
                            .expect("pending calls")
                            .get(&response.id)
                            .cloned();
                        if let Some(call) = call {
                            let outcome = match response.error {
                                Some(error) => Err(FederationPeerError::Rpc(error)),
                                None => Ok(response
                                    .result
                                    .unwrap_or(betterbase_sync_core::protocol::CborValue::Null)),
                            };
                            call.complete(outcome);
                        }
                    }
                    InboundFrame::Chunk(chunk) => {
                        if chunk.frame_type != betterbase_sync_core::protocol::RPC_CHUNK {
                            continue;
                        }
                        let state = state.lock().await;
                        let call = state
                            .pending
                            .lock()
                            .expect("pending calls")
                            .get(&chunk.id)
                            .cloned();
                        if let Some(call) = call {
                            call.push_chunk(ReceivedChunk {
                                name: chunk.name,
                                data: chunk.data,
                            });
                        }
                    }
                    InboundFrame::Notification(notification) => {
                        if notification.frame_type
                            != betterbase_sync_core::protocol::RPC_NOTIFICATION
                        {
                            continue;
                        }
                        // Only accept notifications for spaces this manager
                        // actually subscribed to on the peer — the outgoing
                        // counterpart of the incoming rebroadcast gate.
                        let subscribed = {
                            let spaces = spaces.read().expect("subscription tokens");
                            notification
                                .space
                                .as_deref()
                                .is_some_and(|space| spaces.contains_key(space))
                        };
                        if !subscribed {
                            tracing::warn!(
                                method = notification.method.as_str(),
                                "dropping peer notification for an unsubscribed space"
                            );
                            continue;
                        }
                        notifications(notification.method.as_str(), &notification.params);
                    }
                    InboundFrame::Other => {}
                }
            }
            Message::Close(_) => break,
            Message::Ping(_) | Message::Pong(_) | Message::Text(_) | Message::Frame(_) => {}
        }
    }

    let mut state = state.lock().await;
    // A reader from a reset socket must never close its replacement socket.
    if state.generation == generation {
        teardown(&mut state, timeout).await;
    }
}

async fn connect_socket(
    ws_url: &str,
    key_id: &str,
    signing_key: &SigningKey,
) -> Result<PeerSocket, FederationPeerError> {
    let mut ws_request =
        ws_url
            .into_client_request()
            .map_err(|error| FederationPeerError::InvalidPeerUrl {
                url: ws_url.to_owned(),
                message: error.to_string(),
            })?;

    let mut signature_request = build_signature_request(ws_url)?;
    sign_http_request(&mut signature_request, signing_key, key_id);

    for header_name in ["host", "Signature-Input", "Signature"] {
        if let Some(value) = signature_request.headers().get(header_name) {
            ws_request.headers_mut().insert(header_name, value.clone());
        }
    }
    ws_request.headers_mut().insert(
        SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_static(WS_SUBPROTOCOL),
    );

    let (mut socket, response) = connect_async(ws_request)
        .await
        .map_err(|error| FederationPeerError::Connect(error.to_string()))?;

    let subprotocol = response
        .headers()
        .get(SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    if subprotocol.as_deref() != Some(WS_SUBPROTOCOL) {
        let _ = socket.close(None).await;
        return Err(FederationPeerError::UnexpectedSubprotocol(subprotocol));
    }

    Ok(socket)
}

fn build_signature_request(ws_url: &str) -> Result<Request<()>, FederationPeerError> {
    let url = Url::parse(ws_url).map_err(|error| FederationPeerError::InvalidPeerUrl {
        url: ws_url.to_owned(),
        message: error.to_string(),
    })?;
    if url.scheme() != "ws" && url.scheme() != "wss" {
        return Err(FederationPeerError::InvalidPeerUrl {
            url: ws_url.to_owned(),
            message: "scheme must be ws or wss".to_owned(),
        });
    }

    let mut request = Request::builder()
        .method(Method::GET)
        .uri(ws_url)
        .body(())
        .map_err(|error| FederationPeerError::InvalidPeerUrl {
            url: ws_url.to_owned(),
            message: error.to_string(),
        })?;

    let host = host_header_value(&url).ok_or_else(|| FederationPeerError::InvalidPeerUrl {
        url: ws_url.to_owned(),
        message: "missing host".to_owned(),
    })?;
    let host =
        HeaderValue::from_str(&host).map_err(|error| FederationPeerError::InvalidPeerUrl {
            url: ws_url.to_owned(),
            message: error.to_string(),
        })?;
    request.headers_mut().insert("host", host);

    Ok(request)
}

fn host_header_value(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    match url.port() {
        Some(port) => Some(format!("{host}:{port}")),
        None => Some(host.to_owned()),
    }
}
