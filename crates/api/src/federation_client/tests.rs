use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use less_sync_core::protocol::{
    FederationInvitationParams, PushParams, PushRpcResult, SubscribeResult, WsPullSpace,
    WsPushChange, WsSubscribeSpace, RPC_CHUNK, RPC_RESPONSE,
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
    params: less_sync_core::protocol::CborValue,
}

#[derive(Debug, Clone, serde::Serialize)]
struct OutboundResponseFrame {
    #[serde(rename = "type")]
    frame_type: i32,
    id: String,
    result: less_sync_core::protocol::CborValue,
}

#[derive(Debug, Clone, serde::Serialize)]
struct OutboundChunkFrame {
    #[serde(rename = "type")]
    frame_type: i32,
    id: String,
    name: String,
    data: less_sync_core::protocol::CborValue,
}

#[derive(Debug, Clone)]
enum MockPeerReply {
    Respond {
        result: less_sync_core::protocol::CborValue,
        chunks: Vec<(String, less_sync_core::protocol::CborValue)>,
    },
    CloseConnection,
}

struct MockFederationPeer {
    ws_url: String,
    requests: mpsc::Receiver<InboundRequestFrame>,
    handle: tokio::task::JoinHandle<()>,
}

impl MockFederationPeer {
    async fn spawn(
        responder: impl Fn(InboundRequestFrame) -> MockPeerReply + Send + Sync + 'static,
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
    let mut peer = MockFederationPeer::spawn(|_| MockPeerReply::Respond {
        result: less_sync_core::protocol::CborValue::from_serializable(&SubscribeResult {
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
        .expect("encode subscribe result"),
        chunks: Vec::new(),
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
    let mut peer = MockFederationPeer::spawn(|_| MockPeerReply::Respond {
        result: less_sync_core::protocol::CborValue::Integer(7),
        chunks: Vec::new(),
    })
    .await;
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
    let mut peer = MockFederationPeer::spawn(|_| MockPeerReply::Respond {
        result: less_sync_core::protocol::CborValue::from_serializable(&PushRpcResult {
            ok: true,
            cursor: 42,
            error: String::new(),
        })
        .expect("encode push result"),
        chunks: Vec::new(),
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
    let peer = MockFederationPeer::spawn(|_| MockPeerReply::Respond {
        result: less_sync_core::protocol::CborValue::from_serializable(
            &less_sync_core::protocol::FederationInvitationResult { ok: false },
        )
        .expect("encode invitation result"),
        chunks: Vec::new(),
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
    let mut peer = MockFederationPeer::spawn(|_| MockPeerReply::Respond {
        result: less_sync_core::protocol::CborValue::from_serializable(
            &less_sync_core::protocol::FederationInvitationResult { ok: true },
        )
        .expect("encode invitation result"),
        chunks: Vec::new(),
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

#[tokio::test]
async fn federation_peer_manager_pull_collects_chunk_frames() {
    let mut peer = MockFederationPeer::spawn(|_| MockPeerReply::Respond {
        result: less_sync_core::protocol::CborValue::Null,
        chunks: vec![
            (
                "pull.begin".to_owned(),
                less_sync_core::protocol::CborValue::Integer(1),
            ),
            (
                "pull.record".to_owned(),
                less_sync_core::protocol::CborValue::Bytes(vec![1, 2, 3]),
            ),
        ],
    })
    .await;

    let manager = test_manager(peer.addr());
    let spaces = vec![WsPullSpace {
        id: "space-1".to_owned(),
        since: 42,
        ucan: "ucan-read".to_owned(),
    }];

    let chunks = manager
        .pull("peer.test", &peer.ws_url, &spaces)
        .await
        .expect("pull");
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].name, "pull.begin");
    assert_eq!(
        chunks[0].data,
        less_sync_core::protocol::CborValue::Integer(1)
    );
    assert_eq!(chunks[1].name, "pull.record");
    assert_eq!(
        chunks[1].data,
        less_sync_core::protocol::CborValue::Bytes(vec![1, 2, 3])
    );

    let req = peer.require_request().await;
    assert_eq!(req.method, "pull");
    let got: less_sync_core::protocol::PullParams = decode_params(req.params);
    assert_eq!(got.spaces, spaces);

    manager.close().await;
}

#[tokio::test]
async fn federation_peer_manager_retries_once_when_connection_closes() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_for_responder = Arc::clone(&attempts);

    let mut peer = MockFederationPeer::spawn(move |_| {
        let attempt = attempts_for_responder.fetch_add(1, Ordering::SeqCst);
        if attempt == 0 {
            return MockPeerReply::CloseConnection;
        }
        MockPeerReply::Respond {
            result: less_sync_core::protocol::CborValue::from_serializable(&PushRpcResult {
                ok: true,
                cursor: 7,
                error: String::new(),
            })
            .expect("encode push result"),
            chunks: Vec::new(),
        }
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
            wrapped_dek: None,
        }],
    };

    let result = manager
        .forward_push("peer.test", &peer.ws_url, &params)
        .await
        .expect("forward push should retry");
    assert!(result.ok);
    assert_eq!(result.cursor, 7);

    let first = peer.require_request().await;
    let second = peer.require_request().await;
    assert_eq!(first.method, "push");
    assert_eq!(second.method, "push");
    assert_eq!(first.id, second.id);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);

    manager.close().await;
}

#[tokio::test]
async fn federation_peer_manager_restore_subscriptions_uses_cached_tokens() {
    let mut peer = MockFederationPeer::spawn(|_| MockPeerReply::Respond {
        result: less_sync_core::protocol::CborValue::from_serializable(&SubscribeResult {
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
        .expect("encode subscribe result"),
        chunks: Vec::new(),
    })
    .await;

    let manager = test_manager(peer.addr());
    let initial_spaces = vec![
        WsSubscribeSpace {
            id: "space-1".to_owned(),
            since: 1,
            ucan: "ucan-1".to_owned(),
            token: String::new(),
            presence: false,
        },
        WsSubscribeSpace {
            id: "space-2".to_owned(),
            since: 2,
            ucan: "ucan-2".to_owned(),
            token: String::new(),
            presence: false,
        },
    ];

    manager
        .subscribe("peer.test", &peer.ws_url, &initial_spaces)
        .await
        .expect("initial subscribe");
    let _ = peer.require_request().await;

    manager
        .restore_subscriptions("peer.test", &peer.ws_url)
        .await
        .expect("restore subscriptions");
    let restore_req = peer.require_request().await;
    assert_eq!(restore_req.method, "subscribe");

    let restore_params: less_sync_core::protocol::SubscribeParams =
        decode_params(restore_req.params);
    assert_eq!(restore_params.spaces.len(), 2);
    let token_by_space = restore_params
        .spaces
        .into_iter()
        .map(|space| {
            (
                space.id,
                (space.token, space.since, space.ucan, space.presence),
            )
        })
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(
        token_by_space.get("space-1"),
        Some(&("fst-1".to_owned(), 0, String::new(), false))
    );
    assert_eq!(
        token_by_space.get("space-2"),
        Some(&("fst-2".to_owned(), 0, String::new(), false))
    );

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

fn decode_params<T>(params: less_sync_core::protocol::CborValue) -> T
where
    T: serde::de::DeserializeOwned,
{
    let encoded = minicbor_serde::to_vec(&params).expect("encode params");
    minicbor_serde::from_slice(&encoded).expect("decode params")
}

async fn handle_socket(
    mut socket: WebSocket,
    responder: Arc<dyn Fn(InboundRequestFrame) -> MockPeerReply + Send + Sync>,
    tx: mpsc::Sender<InboundRequestFrame>,
) {
    while let Some(Ok(message)) = socket.next().await {
        let Message::Binary(payload) = message else {
            continue;
        };
        if payload.len() == 1 && payload[0] == 0xF6 {
            continue;
        }

        let request: InboundRequestFrame = match minicbor_serde::from_slice(payload.as_ref()) {
            Ok(request) => request,
            Err(_) => return,
        };
        let _ = tx.send(request.clone()).await;

        match responder(request.clone()) {
            MockPeerReply::Respond { result, chunks } => {
                for (name, data) in chunks {
                    let chunk = OutboundChunkFrame {
                        frame_type: RPC_CHUNK,
                        id: request.id.clone(),
                        name,
                        data,
                    };
                    let encoded = match minicbor_serde::to_vec(&chunk) {
                        Ok(encoded) => encoded,
                        Err(_) => return,
                    };
                    if socket.send(Message::Binary(encoded.into())).await.is_err() {
                        return;
                    }
                }

                let response = OutboundResponseFrame {
                    frame_type: RPC_RESPONSE,
                    id: request.id,
                    result,
                };
                let encoded = match minicbor_serde::to_vec(&response) {
                    Ok(encoded) => encoded,
                    Err(_) => return,
                };
                if socket.send(Message::Binary(encoded.into())).await.is_err() {
                    return;
                }
            }
            MockPeerReply::CloseConnection => {
                let _ = socket.close().await;
                return;
            }
        }
    }
}
