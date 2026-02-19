use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use ed25519_dalek::SigningKey;
use futures_util::StreamExt;
use less_sync_core::protocol::{
    FederationInvitationParams, PushParams, PushRpcResult, SubscribeResult, WsPushChange,
    WsSubscribeSpace, RPC_RESPONSE,
};
use less_sync_realtime::ws::WS_SUBPROTOCOL;
use p256::elliptic_curve::rand_core::OsRng;
use tokio::sync::mpsc;

use super::FederationPeerManager;

#[derive(Debug, Clone, serde::Deserialize)]
struct InboundRequestFrame {
    #[serde(rename = "type")]
    frame_type: i32,
    id: String,
    method: String,
    params: serde_cbor::Value,
}

#[derive(Debug, Clone, serde::Serialize)]
struct OutboundResponseFrame {
    #[serde(rename = "type")]
    frame_type: i32,
    id: String,
    result: serde_cbor::Value,
}

struct MockFederationPeer {
    ws_url: String,
    requests: mpsc::Receiver<InboundRequestFrame>,
    handle: tokio::task::JoinHandle<()>,
}

impl MockFederationPeer {
    async fn spawn(
        responder: impl Fn(InboundRequestFrame) -> serde_cbor::Value + Send + Sync + 'static,
    ) -> Self {
        let responder = Arc::new(responder);
        let (tx, rx) = mpsc::channel(32);

        let app = Router::new().route(
            "/ws",
            get({
                let responder = Arc::clone(&responder);
                move |ws: WebSocketUpgrade| {
                    let responder = Arc::clone(&responder);
                    let tx = tx.clone();
                    async move {
                        ws.protocols([WS_SUBPROTOCOL])
                            .on_upgrade(move |socket| handle_socket(socket, responder, tx))
                            .into_response()
                    }
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        Self {
            ws_url: format!("ws://{addr}/ws"),
            requests: rx,
            handle,
        }
    }

    async fn require_request(&mut self) -> InboundRequestFrame {
        tokio::time::timeout(Duration::from_secs(3), self.requests.recv())
            .await
            .expect("request timeout")
            .expect("request channel closed")
    }

    fn addr(&self) -> SocketAddr {
        self.ws_url
            .trim_start_matches("ws://")
            .split('/')
            .next()
            .expect("host")
            .parse()
            .expect("socket addr")
    }
}

impl Drop for MockFederationPeer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[tokio::test]
async fn federation_peer_manager_subscribe_stores_returned_fsts() {
    let mut peer = MockFederationPeer::spawn(|_| {
        serde_cbor::value::to_value(SubscribeResult {
            spaces: vec![
                less_sync_core::protocol::WsSubscribedSpace {
                    id: "space-1".to_owned(),
                    cursor: 0,
                    key_generation: 0,
                    rewrap_epoch: None,
                    token: "fst-1".to_owned(),
                    peers: Vec::new(),
                },
                less_sync_core::protocol::WsSubscribedSpace {
                    id: "space-2".to_owned(),
                    cursor: 0,
                    key_generation: 0,
                    rewrap_epoch: None,
                    token: "fst-2".to_owned(),
                    peers: Vec::new(),
                },
            ],
            errors: Vec::new(),
        })
        .expect("encode subscribe result")
    })
    .await;

    let manager = test_manager(peer.addr());
    let spaces = vec![
        WsSubscribeSpace {
            id: "space-1".to_owned(),
            since: 10,
            ucan: "ucan-1".to_owned(),
            token: String::new(),
            presence: false,
        },
        WsSubscribeSpace {
            id: "space-2".to_owned(),
            since: 20,
            ucan: "ucan-2".to_owned(),
            token: String::new(),
            presence: false,
        },
    ];

    manager
        .subscribe("peer.test", &peer.ws_url, &spaces)
        .await
        .expect("subscribe");

    let req = peer.require_request().await;
    assert_eq!(req.method, "subscribe");
    assert_eq!(req.frame_type, less_sync_core::protocol::RPC_REQUEST);
    let params: less_sync_core::protocol::SubscribeParams = decode_params(req.params);
    assert_eq!(params.spaces.len(), 2);
    assert_eq!(params.spaces[0].id, "space-1");
    assert_eq!(params.spaces[1].id, "space-2");

    let tokens = peer_tokens(&manager, "peer.test").await;
    assert_eq!(tokens.get("space-1"), Some(&"fst-1".to_owned()));
    assert_eq!(tokens.get("space-2"), Some(&"fst-2".to_owned()));

    manager.close().await;
}

#[tokio::test]
async fn federation_peer_manager_subscribe_fallback_tracks_spaces_on_decode_failure() {
    let mut peer = MockFederationPeer::spawn(|_| serde_cbor::Value::Integer(7)).await;
    let manager = test_manager(peer.addr());

    let spaces = vec![
        WsSubscribeSpace {
            id: "space-a".to_owned(),
            since: 1,
            ucan: String::new(),
            token: String::new(),
            presence: false,
        },
        WsSubscribeSpace {
            id: "space-b".to_owned(),
            since: 2,
            ucan: String::new(),
            token: String::new(),
            presence: false,
        },
    ];

    manager
        .subscribe("peer.test", &peer.ws_url, &spaces)
        .await
        .expect("subscribe fallback");

    let _ = peer.require_request().await;
    let tokens = peer_tokens(&manager, "peer.test").await;
    assert_eq!(tokens.get("space-a"), Some(&String::new()));
    assert_eq!(tokens.get("space-b"), Some(&String::new()));

    manager.close().await;
}

#[tokio::test]
async fn federation_peer_manager_forward_push_forwards_and_decodes() {
    let mut peer = MockFederationPeer::spawn(|_| {
        serde_cbor::value::to_value(PushRpcResult {
            ok: true,
            cursor: 42,
            error: String::new(),
        })
        .expect("encode push result")
    })
    .await;

    let manager = test_manager(peer.addr());
    let params = PushParams {
        space: "space-1".to_owned(),
        ucan: "ucan-write".to_owned(),
        changes: vec![WsPushChange {
            id: "00000000-0000-0000-0000-000000000001".to_owned(),
            blob: Some(vec![120]),
            expected_cursor: 0,
            wrapped_dek: Some(vec![1, 2, 3]),
        }],
    };

    let result = manager
        .forward_push("peer.test", &peer.ws_url, &params)
        .await
        .expect("forward push");
    assert!(result.ok);
    assert_eq!(result.cursor, 42);

    let req = peer.require_request().await;
    assert_eq!(req.method, "push");
    let got: PushParams = decode_params(req.params);
    assert_eq!(got.space, params.space);
    assert_eq!(got.changes.len(), 1);
    assert_eq!(got.changes[0].id, params.changes[0].id);

    manager.close().await;
}

#[tokio::test]
async fn federation_peer_manager_forward_invitation_rejects_not_ok() {
    let peer = MockFederationPeer::spawn(|_| {
        serde_cbor::value::to_value(less_sync_core::protocol::FederationInvitationResult {
            ok: false,
        })
        .expect("encode invitation result")
    })
    .await;

    let manager = test_manager(peer.addr());
    let error = manager
        .forward_invitation(
            "peer.test",
            &peer.ws_url,
            &FederationInvitationParams {
                mailbox_id: "a".repeat(64),
                payload: "payload".to_owned(),
            },
        )
        .await
        .expect_err("forward invitation should fail");
    assert!(error.to_string().contains("rejected"));

    manager.close().await;
}

#[tokio::test]
async fn federation_peer_manager_forward_invitation_forwards_params() {
    let mut peer = MockFederationPeer::spawn(|_| {
        serde_cbor::value::to_value(less_sync_core::protocol::FederationInvitationResult {
            ok: true,
        })
        .expect("encode invitation result")
    })
    .await;

    let manager = test_manager(peer.addr());
    let params = FederationInvitationParams {
        mailbox_id: "b".repeat(64),
        payload: "encrypted-payload".to_owned(),
    };

    manager
        .forward_invitation("peer.test", &peer.ws_url, &params)
        .await
        .expect("forward invitation");

    let req = peer.require_request().await;
    assert_eq!(req.method, "fed.invitation");
    let got: FederationInvitationParams = decode_params(req.params);
    assert_eq!(got.mailbox_id, params.mailbox_id);
    assert_eq!(got.payload, params.payload);

    manager.close().await;
}

fn test_manager(addr: SocketAddr) -> FederationPeerManager {
    let signing_key = SigningKey::generate(&mut OsRng);
    let key_id = format!("https://{addr}/.well-known/jwks.json#fed-test");
    FederationPeerManager::new(key_id, signing_key)
}

async fn peer_tokens(
    manager: &FederationPeerManager,
    domain: &str,
) -> std::collections::HashMap<String, String> {
    let peer = {
        let peers = manager.peers.lock().await;
        peers.get(domain).cloned().expect("peer connection")
    };
    peer.space_tokens().await
}

fn decode_params<T>(params: serde_cbor::Value) -> T
where
    T: serde::de::DeserializeOwned,
{
    let encoded = serde_cbor::to_vec(&params).expect("encode params");
    serde_cbor::from_slice(&encoded).expect("decode params")
}

async fn handle_socket(
    mut socket: WebSocket,
    responder: Arc<dyn Fn(InboundRequestFrame) -> serde_cbor::Value + Send + Sync>,
    tx: mpsc::Sender<InboundRequestFrame>,
) {
    while let Some(Ok(message)) = socket.next().await {
        let Message::Binary(payload) = message else {
            continue;
        };
        if payload.len() == 1 && payload[0] == 0xF6 {
            continue;
        }

        let request: InboundRequestFrame = match serde_cbor::from_slice(payload.as_ref()) {
            Ok(request) => request,
            Err(_) => return,
        };
        let _ = tx.send(request.clone()).await;

        let result = responder(request.clone());
        let response = OutboundResponseFrame {
            frame_type: RPC_RESPONSE,
            id: request.id,
            result,
        };
        let encoded = match serde_cbor::to_vec(&response) {
            Ok(encoded) => encoded,
            Err(_) => return,
        };
        if socket.send(Message::Binary(encoded.into())).await.is_err() {
            return;
        }
    }
}
