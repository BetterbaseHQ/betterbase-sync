use std::collections::HashMap;

use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use http::header::SEC_WEBSOCKET_PROTOCOL;
use http::{HeaderValue, Method, Request};
use less_sync_auth::sign_http_request;
use less_sync_realtime::ws::WS_SUBPROTOCOL;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use url::Url;

use super::wire::{decode_inbound_frame, encode_request_frame, InboundFrame};
use super::FederationPeerError;

type PeerSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub(super) struct PeerConnection {
    ws_url: String,
    socket: Mutex<Option<PeerSocket>>,
    spaces: RwLock<HashMap<String, String>>,
}

impl PeerConnection {
    pub(super) fn new(_domain: String, ws_url: String) -> Self {
        Self {
            ws_url,
            socket: Mutex::new(None),
            spaces: RwLock::new(HashMap::new()),
        }
    }

    pub(super) async fn call_raw<P>(
        &self,
        key_id: &str,
        signing_key: &SigningKey,
        request_id: &str,
        method: &str,
        params: &P,
    ) -> Result<serde_cbor::Value, FederationPeerError>
    where
        P: serde::Serialize,
    {
        let frame = encode_request_frame(request_id, method, params)?;
        let mut socket = self.socket.lock().await;

        if socket.is_none() {
            *socket = Some(connect_socket(&self.ws_url, key_id, signing_key).await?);
        }

        let active_socket = socket
            .as_mut()
            .ok_or_else(|| FederationPeerError::Connect("missing active socket".to_owned()))?;

        if active_socket
            .send(Message::Binary(frame.into()))
            .await
            .is_err()
        {
            *socket = None;
            return Err(FederationPeerError::Closed);
        }

        let result = read_response_for_request(active_socket, request_id).await;
        if result.is_err() {
            *socket = None;
        }
        result
    }

    pub(super) async fn set_space_tokens(&self, token_by_space: HashMap<String, String>) {
        let mut spaces = self.spaces.write().await;
        for (space, token) in token_by_space {
            spaces.insert(space, token);
        }
    }

    #[cfg(test)]
    pub(super) async fn space_tokens(&self) -> HashMap<String, String> {
        self.spaces.read().await.clone()
    }

    pub(super) async fn close(&self) {
        let mut socket = self.socket.lock().await;
        if let Some(active) = socket.as_mut() {
            let _ = active.close(None).await;
        }
        *socket = None;
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

async fn read_response_for_request(
    socket: &mut PeerSocket,
    request_id: &str,
) -> Result<serde_cbor::Value, FederationPeerError> {
    while let Some(frame) = socket.next().await {
        let frame = frame.map_err(|_| FederationPeerError::Closed)?;
        match frame {
            Message::Binary(payload) => {
                if payload.len() == 1 && payload[0] == 0xF6 {
                    continue;
                }

                match decode_inbound_frame(payload.as_ref())? {
                    InboundFrame::Response(response) => {
                        if response.frame_type != less_sync_core::protocol::RPC_RESPONSE {
                            continue;
                        }
                        if response.id != request_id {
                            continue;
                        }
                        if let Some(error) = response.error {
                            return Err(FederationPeerError::Rpc(error));
                        }
                        return Ok(response.result.unwrap_or(serde_cbor::Value::Null));
                    }
                    InboundFrame::Chunk | InboundFrame::Other => {
                        continue;
                    }
                }
            }
            Message::Close(_) => return Err(FederationPeerError::Closed),
            Message::Ping(_) | Message::Pong(_) | Message::Text(_) | Message::Frame(_) => {}
        }
    }

    Err(FederationPeerError::Closed)
}
