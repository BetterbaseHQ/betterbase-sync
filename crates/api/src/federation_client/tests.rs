use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use betterbase_sync_core::protocol::{
    FederationInvitationParams, PushParams, PushRpcResult, SubscribeResult, WsPullSpace,
    WsPushChange, WsSubscribeSpace, RPC_CHUNK, RPC_RESPONSE,
};
use betterbase_sync_realtime::ws::WS_SUBPROTOCOL;
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use rand_core::OsRng;
use tokio::sync::mpsc;

use super::FederationPeerManager;

#[derive(Debug, Clone, serde::Deserialize)]
struct InboundRequestFrame {
    #[serde(rename = "type")]
    frame_type: i32,
    id: String,
    method: String,
    params: betterbase_sync_core::protocol::CborValue,
}

#[derive(Debug, Clone, serde::Serialize)]
struct OutboundResponseFrame {
    #[serde(rename = "type")]
    frame_type: i32,
    id: String,
    result: betterbase_sync_core::protocol::CborValue,
}

#[derive(Debug, Clone, serde::Serialize)]
struct OutboundChunkFrame {
    #[serde(rename = "type")]
    frame_type: i32,
    id: String,
    name: String,
    data: betterbase_sync_core::protocol::CborValue,
}

#[derive(Debug, Clone)]
enum MockPeerReply {
    Respond {
        result: betterbase_sync_core::protocol::CborValue,
        chunks: Vec<(String, betterbase_sync_core::protocol::CborValue)>,
    },
    /// Push a notification frame before answering — mirrors a peer whose
    /// subscribe landed server-side and started rebroadcasting immediately.
    NotifyThenRespond {
        method: &'static str,
        params: betterbase_sync_core::protocol::CborValue,
        result: betterbase_sync_core::protocol::CborValue,
    },
    CloseConnection,
    Stall,
    RpcError,
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
        result: betterbase_sync_core::protocol::CborValue::from_serializable(&SubscribeResult {
            spaces: vec![
                betterbase_sync_core::protocol::WsSubscribedSpace {
                    id: "space-1".to_owned(),
                    cursor: 0,
                    epoch: 0,
                    rewrap_epoch: None,
                    token: "fst-1".to_owned(),
                    peers: Vec::new(),
                },
                betterbase_sync_core::protocol::WsSubscribedSpace {
                    id: "space-2".to_owned(),
                    cursor: 0,
                    epoch: 0,
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
    assert_eq!(req.frame_type, betterbase_sync_core::protocol::RPC_REQUEST);
    let params: betterbase_sync_core::protocol::SubscribeParams = decode_params(req.params);
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
        result: betterbase_sync_core::protocol::CborValue::Integer(7),
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
        result: betterbase_sync_core::protocol::CborValue::from_serializable(&PushRpcResult {
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
        epoch: 0,
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
        result: betterbase_sync_core::protocol::CborValue::from_serializable(
            &betterbase_sync_core::protocol::FederationInvitationResult { ok: false },
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
        result: betterbase_sync_core::protocol::CborValue::from_serializable(
            &betterbase_sync_core::protocol::FederationInvitationResult { ok: true },
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
        result: betterbase_sync_core::protocol::CborValue::Null,
        chunks: vec![
            (
                "pull.begin".to_owned(),
                betterbase_sync_core::protocol::CborValue::Integer(1),
            ),
            (
                "pull.record".to_owned(),
                betterbase_sync_core::protocol::CborValue::Bytes(vec![1, 2, 3]),
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
        betterbase_sync_core::protocol::CborValue::Integer(1)
    );
    assert_eq!(chunks[1].name, "pull.record");
    assert_eq!(
        chunks[1].data,
        betterbase_sync_core::protocol::CborValue::Bytes(vec![1, 2, 3])
    );

    let req = peer.require_request().await;
    assert_eq!(req.method, "pull");
    let got: betterbase_sync_core::protocol::PullParams = decode_params(req.params);
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
            result: betterbase_sync_core::protocol::CborValue::from_serializable(&PushRpcResult {
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
        epoch: 0,
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
    // A fresh request id per attempt keeps the old reader's late frames
    // from completing the new attempt's slot.
    assert_ne!(first.id, second.id);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);

    manager.close().await;
}

#[tokio::test]
async fn federation_peer_manager_restore_subscriptions_uses_cached_tokens() {
    let mut peer = MockFederationPeer::spawn(|_| MockPeerReply::Respond {
        result: betterbase_sync_core::protocol::CborValue::from_serializable(&SubscribeResult {
            spaces: vec![
                betterbase_sync_core::protocol::WsSubscribedSpace {
                    id: "space-1".to_owned(),
                    cursor: 0,
                    epoch: 0,
                    rewrap_epoch: None,
                    token: "fst-1".to_owned(),
                    peers: Vec::new(),
                },
                betterbase_sync_core::protocol::WsSubscribedSpace {
                    id: "space-2".to_owned(),
                    cursor: 0,
                    epoch: 0,
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

    let restore_params: betterbase_sync_core::protocol::SubscribeParams =
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

#[tokio::test]
async fn federation_peer_manager_delivers_notifications_during_call() {
    // AUD-037: the old reader consumed the socket only while awaiting one
    // RPC response and discarded every notification frame it saw. The
    // dedicated reader must deliver notifications AND complete the call.
    let mut peer = MockFederationPeer::spawn(|_| MockPeerReply::NotifyThenRespond {
        method: "sync",
        params: betterbase_sync_core::protocol::CborValue::from_serializable(&serde_json::json!({
            "space": "space-1",
            "prev": 0,
            "cursor": 5,
            "epoch": 0,
            "records": [{ "id": "record-1", "cursor": 5 }]
        }))
        .expect("encode notification params"),
        result: betterbase_sync_core::protocol::CborValue::from_serializable(&SubscribeResult {
            spaces: vec![betterbase_sync_core::protocol::WsSubscribedSpace {
                id: "space-1".to_owned(),
                cursor: 0,
                epoch: 0,
                rewrap_epoch: None,
                token: "fst-1".to_owned(),
                peers: Vec::new(),
            }],
            errors: Vec::new(),
        })
        .expect("encode subscribe result"),
    })
    .await;

    let (notifications_tx, mut notifications_rx) = mpsc::unbounded_channel();
    let manager = test_manager(peer.addr()).with_notification_handler(Arc::new(
        move |method: &str, params: &betterbase_sync_core::protocol::CborValue| {
            notifications_tx
                .send((method.to_owned(), params.clone()))
                .expect("notification channel open");
        },
    ));

    manager
        .subscribe(
            "peer.test",
            &peer.ws_url,
            &[WsSubscribeSpace {
                id: "space-1".to_owned(),
                since: 0,
                ucan: String::new(),
                token: String::new(),
                presence: false,
            }],
        )
        .await
        .expect("subscribe completes despite interleaved notification");

    let _ = peer.require_request().await;

    let (method, params) = tokio::time::timeout(Duration::from_secs(3), notifications_rx.recv())
        .await
        .expect("notification must be delivered")
        .expect("notification channel open");
    assert_eq!(method, "sync");
    let decoded: serde_json::Value = decode_params(params);
    assert_eq!(decoded["space"], "space-1");
    assert_eq!(decoded["cursor"], 5);

    manager.close().await;
}

#[tokio::test]
async fn federation_peer_manager_drops_notifications_for_unsubscribed_spaces() {
    // The outgoing counterpart of the incoming rebroadcast gate: a peer
    // pushing notifications for spaces this manager never subscribed to
    // must not reach the local broker.
    let mut peer = MockFederationPeer::spawn(|_| MockPeerReply::NotifyThenRespond {
        method: "sync",
        params: betterbase_sync_core::protocol::CborValue::from_serializable(&serde_json::json!({
            "space": "space-not-subscribed",
            "prev": 0,
            "cursor": 1,
            "epoch": 0,
            "records": [{ "id": "record-x", "cursor": 1 }]
        }))
        .expect("encode notification params"),
        result: betterbase_sync_core::protocol::CborValue::from_serializable(&PushRpcResult {
            ok: true,
            cursor: 1,
            error: String::new(),
        })
        .expect("encode push result"),
    })
    .await;

    let (notifications_tx, mut notifications_rx) = mpsc::unbounded_channel();
    let manager = test_manager(peer.addr()).with_notification_handler(Arc::new(
        move |method: &str, params: &betterbase_sync_core::protocol::CborValue| {
            notifications_tx
                .send((method.to_owned(), params.clone()))
                .expect("notification channel open");
        },
    ));

    // forward_push opens the connection without any subscription.
    let result = manager
        .forward_push(
            "peer.test",
            &peer.ws_url,
            &PushParams {
                epoch: 0,
                space: "space-1".to_owned(),
                ucan: "ucan-write".to_owned(),
                changes: vec![WsPushChange {
                    id: "00000000-0000-0000-0000-000000000001".to_owned(),
                    blob: Some(vec![120]),
                    expected_cursor: 0,
                    wrapped_dek: None,
                }],
            },
        )
        .await
        .expect("forward push");
    assert!(result.ok);
    let _ = peer.require_request().await;

    let leaked = tokio::time::timeout(Duration::from_millis(250), notifications_rx.recv()).await;
    assert!(
        leaked.is_err(),
        "notification for an unsubscribed space must be dropped"
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

fn decode_params<T>(params: betterbase_sync_core::protocol::CborValue) -> T
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
            MockPeerReply::NotifyThenRespond {
                method,
                params,
                result,
            } => {
                #[derive(serde::Serialize)]
                struct OutboundNotificationFrame {
                    #[serde(rename = "type")]
                    frame_type: i32,
                    method: &'static str,
                    params: betterbase_sync_core::protocol::CborValue,
                }
                let notification = OutboundNotificationFrame {
                    frame_type: betterbase_sync_core::protocol::RPC_NOTIFICATION,
                    method,
                    params,
                };
                let encoded = match minicbor_serde::to_vec(&notification) {
                    Ok(encoded) => encoded,
                    Err(_) => return,
                };
                if socket.send(Message::Binary(encoded.into())).await.is_err() {
                    return;
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
            MockPeerReply::RpcError => {
                #[derive(serde::Serialize)]
                struct ErrorFrame {
                    #[serde(rename = "type")]
                    kind: i32,
                    id: String,
                    error: betterbase_sync_core::protocol::RpcError,
                }
                let response = ErrorFrame {
                    kind: RPC_RESPONSE,
                    id: request.id,
                    error: betterbase_sync_core::protocol::RpcError {
                        code: "rate_limited".into(),
                        message: "quota".into(),
                    },
                };
                socket
                    .send(Message::Binary(
                        minicbor_serde::to_vec(&response).expect("error").into(),
                    ))
                    .await
                    .expect("send error");
            }
            MockPeerReply::Stall => {}
            MockPeerReply::CloseConnection => {
                let _ = socket.close().await;
                return;
            }
        }
    }
}

async fn deadline_manager(peer: &MockFederationPeer) -> Arc<FederationPeerManager> {
    let manager = Arc::new(test_manager(peer.addr()));
    let connection = super::peer::PeerConnection::new(
        "deadline.example".into(),
        peer.ws_url.clone(),
        Arc::new(|_, _| {}),
    )
    .with_response_timeout(Duration::from_millis(250));
    manager
        .peers
        .lock()
        .await
        .insert("deadline.example".into(), Arc::new(connection));
    manager
}
fn deadline_push() -> PushParams {
    PushParams {
        space: uuid::Uuid::new_v4().to_string(),
        epoch: 0,
        ucan: String::new(),
        changes: Vec::new(),
    }
}
fn push_reply() -> MockPeerReply {
    MockPeerReply::Respond {
        result: betterbase_sync_core::protocol::CborValue::from_serializable(&PushRpcResult {
            ok: true,
            cursor: 1,
            error: String::new(),
        })
        .expect("push"),
        chunks: Vec::new(),
    }
}

#[tokio::test]
async fn stalled_peer_times_out_retries_once_and_next_call_recovers() {
    let stalled = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let switch = stalled.clone();
    let mut peer = MockFederationPeer::spawn(move |_| {
        if switch.load(Ordering::SeqCst) {
            MockPeerReply::Stall
        } else {
            push_reply()
        }
    })
    .await;
    let manager = deadline_manager(&peer).await;
    let error = tokio::time::timeout(
        Duration::from_secs(3),
        manager.forward_push("deadline.example", &peer.ws_url, &deadline_push()),
    )
    .await
    .expect("bounded deadline")
    .expect_err("stalled peer");
    assert!(matches!(error, super::FederationPeerError::Closed));
    let first = peer.require_request().await;
    let second = peer.require_request().await;
    assert_ne!(first.id, second.id);
    assert_eq!(
        manager
            .peers
            .lock()
            .await
            .get("deadline.example")
            .expect("peer")
            .pending_count()
            .await,
        0
    );
    stalled.store(false, Ordering::SeqCst);
    assert!(
        manager
            .forward_push("deadline.example", &peer.ws_url, &deadline_push())
            .await
            .expect("recovered")
            .ok
    );
    manager.close().await;
}

#[tokio::test]
async fn cancelled_peer_call_does_not_retain_pending_response_or_break_other_calls() {
    let stalled = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let switch = stalled.clone();
    let mut peer = MockFederationPeer::spawn(move |_| {
        if switch.load(Ordering::SeqCst) {
            MockPeerReply::Stall
        } else {
            push_reply()
        }
    })
    .await;
    let manager = Arc::new(test_manager(peer.addr()));
    let url = peer.ws_url.clone();
    let caller = manager.clone();
    let task = tokio::spawn(async move {
        caller
            .forward_push("cancel.example", &url, &deadline_push())
            .await
    });
    peer.require_request().await;
    task.abort();
    assert!(task.await.expect_err("cancelled").is_cancelled());
    let connection = manager
        .peers
        .lock()
        .await
        .get("cancel.example")
        .expect("peer")
        .clone();
    assert_eq!(
        connection.pending_count().await,
        0,
        "cancelled calls must not retain chunk buffers"
    );
    stalled.store(false, Ordering::SeqCst);
    assert!(
        manager
            .forward_push("cancel.example", &peer.ws_url, &deadline_push())
            .await
            .expect("other call works")
            .ok
    );
    manager.close().await;
}

#[tokio::test]
async fn rejected_subscribe_does_not_leave_requested_spaces_in_notification_gate() {
    let mut peer = MockFederationPeer::spawn(|_| MockPeerReply::RpcError).await;
    let manager = test_manager(peer.addr());
    let space = uuid::Uuid::new_v4().to_string();
    let result = manager
        .subscribe(
            "rejected.example",
            &peer.ws_url,
            &[WsSubscribeSpace {
                id: space.clone(),
                since: 0,
                ucan: "test".into(),
                token: String::new(),
                presence: false,
            }],
        )
        .await;
    assert!(matches!(result, Err(super::FederationPeerError::Rpc(_))));
    peer.require_request().await;
    assert!(!peer_tokens(&manager, "rejected.example")
        .await
        .contains_key(&space));
    manager.close().await;
}

#[tokio::test]
async fn cancelled_subscribe_rolls_back_notification_gate_and_preserves_previous_tokens() {
    let mut peer = MockFederationPeer::spawn(|_| MockPeerReply::Stall).await;
    let manager = Arc::new(test_manager(peer.addr()));
    let connection = manager
        .get_or_create_peer("cancel-sub.example", &peer.ws_url)
        .await;
    connection
        .set_space_tokens(HashMap::from([("existing".into(), "old-fst".into())]))
        .await;
    let caller = manager.clone();
    let url = peer.ws_url.clone();
    let task = tokio::spawn(async move {
        caller
            .subscribe(
                "cancel-sub.example",
                &url,
                &["existing", "new"].map(|id| WsSubscribeSpace {
                    id: id.into(),
                    since: 0,
                    ucan: "test".into(),
                    token: String::new(),
                    presence: false,
                }),
            )
            .await
    });
    peer.require_request().await;
    task.abort();
    assert!(task.await.expect_err("cancelled").is_cancelled());
    assert_eq!(
        connection.space_tokens().await,
        HashMap::from([("existing".into(), "old-fst".into())])
    );
    manager.close().await;
}

#[tokio::test]
async fn stalled_websocket_handshake_is_deadline_bounded() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let addr = listener.local_addr().expect("address");
    let (accepted_tx, mut accepted_rx) = mpsc::unbounded_channel();
    let server = tokio::spawn(async move {
        let mut sockets = Vec::new();
        loop {
            let (socket, _) = listener.accept().await.expect("accept");
            sockets.push(socket);
            let _ = accepted_tx.send(());
        }
    });
    let manager = test_manager(addr);
    let url = format!("ws://{addr}/ws");
    manager.peers.lock().await.insert(
        "handshake.example".into(),
        Arc::new(
            super::peer::PeerConnection::new(
                "handshake.example".into(),
                url.clone(),
                Arc::new(|_, _| {}),
            )
            .with_response_timeout(Duration::from_millis(250)),
        ),
    );
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        manager.forward_push("handshake.example", &url, &deadline_push()),
    )
    .await
    .expect("bounded handshake");
    assert!(matches!(result, Err(super::FederationPeerError::Closed)));
    assert!(accepted_rx.try_recv().is_ok());
    assert!(accepted_rx.try_recv().is_ok());
    assert!(accepted_rx.try_recv().is_err());
    manager.close().await;
    server.abort();
}

#[tokio::test]
async fn closing_manager_fails_inflight_call_without_reconnecting_it() {
    let mut peer = MockFederationPeer::spawn(|_| MockPeerReply::Stall).await;
    let manager = Arc::new(test_manager(peer.addr()));
    let caller = manager.clone();
    let url = peer.ws_url.clone();
    let task = tokio::spawn(async move {
        caller
            .forward_push("close.example", &url, &deadline_push())
            .await
    });
    peer.require_request().await;
    manager.close().await;
    let result = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("shutdown releases caller")
        .expect("caller task");
    assert!(matches!(result, Err(super::FederationPeerError::Closed)));
    assert!(
        peer.requests.try_recv().is_err(),
        "shutdown must not reconnect an in-flight call"
    );
}

#[tokio::test]
async fn concurrent_calls_recover_from_a_reset_without_closing_each_others_replacement() {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let peer = MockFederationPeer::spawn(move |_| {
        if count.fetch_add(1, Ordering::SeqCst) == 0 {
            MockPeerReply::CloseConnection
        } else {
            push_reply()
        }
    })
    .await;
    let manager = Arc::new(test_manager(peer.addr()));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let caller = manager.clone();
        let url = peer.ws_url.clone();
        tasks.spawn(async move {
            caller
                .forward_push("concurrent.example", &url, &deadline_push())
                .await
        });
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(result) = tasks.join_next().await {
            assert!(result.expect("caller").expect("recovered call").ok);
        }
    })
    .await
    .expect("bounded recovery");
    manager.close().await;
}
