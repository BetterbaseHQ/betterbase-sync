//! Two real HTTP/WebSocket servers, isolated PostgreSQL schemas, and a cuttable TCP link.
use super::postgres_tests::TestDatabase;
use super::*;
use crate::FederationPeerManager;
use betterbase_sync_core::protocol::*;
use betterbase_sync_storage::SpaceStorage;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::{mpsc, watch};

const KEY_ID: &str = "https://peer.example.com/.well-known/jwks.json#integration";
const PEER: &str = "peer.example.com";

struct Link {
    addr: SocketAddr,
    reset: watch::Sender<u64>,
    accepted: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}
impl Link {
    async fn new(target: SocketAddr) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("proxy");
        let addr = listener.local_addr().expect("proxy address");
        let (reset, rx) = watch::channel(0);
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = accepted.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        let (mut downstream, _) = result.expect("accept");
                        count.fetch_add(1, Ordering::SeqCst);
                        let mut resets = rx.clone();
                        // A reset cuts only sockets accepted before it.
                        resets.borrow_and_update();
                        connections.spawn(async move {
                            let mut upstream = tokio::net::TcpStream::connect(target).await.expect("upstream");
                            tokio::select! {
                                _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream) => {},
                                _ = resets.changed() => {},
                            }
                        });
                    },
                    _ = connections.join_next(), if !connections.is_empty() => {},
                }
            }
        });
        Self {
            addr,
            reset,
            accepted,
            task,
        }
    }
    fn cut(&self) {
        self.reset.send_modify(|generation| *generation += 1);
    }
    fn url(&self) -> String {
        format!("ws://{}/api/v1/federation/ws", self.addr)
    }
}
impl Drop for Link {
    fn drop(&mut self) {
        self.task.abort();
    }
}
struct Server(TestServer);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.handle.abort();
    }
}

struct Pair {
    home: Server,
    edge: Server,
    link: Link,
    home_db: TestDatabase,
    edge_db: TestDatabase,
    manager: Arc<FederationPeerManager>,
    quota: Arc<crate::FederationQuotaTracker>,
    signing_key: Ed25519SigningKey,
    root: TestIssuer,
    delegate: TestIssuer,
    space: Uuid,
    notifications: mpsc::UnboundedReceiver<(String, CborValue)>,
}
impl Pair {
    async fn new(limits: FederationQuotaLimits) -> Option<Self> {
        let home_db = TestDatabase::new().await?;
        let edge_db = TestDatabase::new().await.expect("second database");
        let root = TestIssuer::new();
        let delegate = TestIssuer::new();
        let space = Uuid::new_v4();
        for db in [&home_db, &edge_db] {
            SpaceStorage::create_space(
                &*db.storage,
                space,
                "shared",
                Some(&root.compressed_public_key()),
            )
            .await
            .expect("space");
        }
        let signing_key = Ed25519SigningKey::generate(&mut OsRng);
        let home_state = with_federation_auth(
            base_state_with_ws(Duration::from_secs(1), "sync")
                .with_sync_storage(home_db.storage.clone())
                .with_realtime_broker(Arc::new(MultiBroker::new(BrokerConfig::default())))
                .with_federation_token_keys(FederationTokenKeys::new(derive_fst_key(
                    b"integration",
                )))
                .with_federation_quota_limits(limits),
            &signing_key,
            KEY_ID,
        );
        let quota = home_state.federation_quota_tracker();
        let home = Server(spawn_server(home_state).await);
        let link = Link::new(home.0.addr).await;
        sqlx::query("UPDATE spaces SET home_server = $2 WHERE id = $1")
            .bind(space)
            .bind(format!("http://{}", link.addr))
            .execute(edge_db.storage.pool())
            .await
            .expect("home server");
        let (tx, notifications) = mpsc::unbounded_channel();
        let manager = Arc::new(
            FederationPeerManager::new(KEY_ID, signing_key.clone()).with_notification_handler(
                Arc::new(move |method, params| {
                    let _ = tx.send((method.to_owned(), params.clone()));
                }),
            ),
        );
        let validator = StubValidator {
            tokens: HashMap::from([(
                "valid-token".into(),
                test_auth_context_with_did("sync", &delegate.did),
            )]),
        };
        let edge = Server(
            spawn_server(
                base_state_with_ws_validator(Duration::from_secs(1), Arc::new(validator))
                    .with_sync_storage(edge_db.storage.clone())
                    .with_realtime_broker(Arc::new(MultiBroker::new(BrokerConfig::default())))
                    .with_federation_forwarder(manager.clone()),
            )
            .await,
        );
        Some(Self {
            home,
            edge,
            link,
            home_db,
            edge_db,
            manager,
            quota,
            signing_key,
            root,
            delegate,
            space,
            notifications,
        })
    }
    fn read(&self) -> String {
        self.root
            .issue_space_ucan(&self.delegate.did, self.space, Permission::Read)
    }
    fn write(&self) -> String {
        self.root
            .issue_space_ucan(&self.delegate.did, self.space, Permission::Write)
    }
    fn subscription(&self) -> WsSubscribeSpace {
        WsSubscribeSpace {
            id: self.space.to_string(),
            since: 0,
            ucan: self.read(),
            token: String::new(),
            presence: false,
        }
    }
    fn push(&self, id: Uuid, expected: i64, bytes: &[u8]) -> PushParams {
        PushParams {
            space: self.space.to_string(),
            epoch: 1,
            ucan: self.write(),
            changes: vec![WsPushChange {
                id: id.to_string(),
                blob: Some(bytes.to_vec()),
                expected_cursor: expected,
                wrapped_dek: Some(wrapper()),
            }],
        }
    }
    async fn client(&self) -> TestSocket {
        let (mut socket, _) = connect_async(ws_request(
            self.edge.0.addr,
            Some(betterbase_sync_realtime::ws::WS_SUBPROTOCOL),
        ))
        .await
        .expect("edge client");
        send_auth(&mut socket).await;
        socket
    }
    async fn peer(&self) -> TestSocket {
        connect_async(signed_federation_ws_request(
            self.home.0.addr,
            &self.signing_key,
            KEY_ID,
        ))
        .await
        .expect("signed peer")
        .0
    }
    async fn usage(&self, connections: usize, spaces: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let status = self.quota.peer_status(PEER).await;
                if status.connections == connections && status.spaces == spaces {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("quota state settles");
    }
    async fn finish(self) {
        self.manager.close().await;
        self.usage(0, 0).await;
        let Self {
            home,
            edge,
            link,
            home_db,
            edge_db,
            ..
        } = self;
        home.0.handle.abort();
        edge.0.handle.abort();
        drop((home, edge, link));
        home_db.close().await;
        edge_db.close().await;
    }
}
fn wrapper() -> Vec<u8> {
    let mut dek = vec![9; 44];
    dek[..4].copy_from_slice(&1_i32.to_be_bytes());
    dek
}
fn limits() -> FederationQuotaLimits {
    FederationQuotaLimits {
        max_connections: 4,
        max_spaces: 4,
        max_records_per_hour: 100,
        max_bytes_per_hour: 10000,
        ..FederationQuotaLimits::default()
    }
}
async fn rpc<P: serde::Serialize, R: for<'de> Deserialize<'de>>(
    socket: &mut TestSocket,
    method: &str,
    params: &P,
) -> R {
    send_rpc_request(socket, method, method, params).await;
    read_result_response::<R>(socket).await.result
}
fn decode<T: for<'de> Deserialize<'de>>(value: &CborValue) -> T {
    minicbor_serde::from_slice(&minicbor_serde::to_vec(value).expect("encode")).expect("decode")
}

#[tokio::test]
async fn edge_forwards_push_and_streaming_pull_to_real_home_without_local_writes() {
    let Some(p) = Pair::new(limits()).await else {
        return;
    };
    let mut client = p.client().await;
    let subscribed: SubscribeResult = rpc(
        &mut client,
        "subscribe",
        &SubscribeParams {
            spaces: vec![p.subscription()],
        },
    )
    .await;
    assert!(subscribed.errors.is_empty());
    assert_eq!(subscribed.spaces.len(), 1);
    let record = Uuid::new_v4();
    let pushed: PushRpcResult = rpc(&mut client, "push", &p.push(record, 0, &[0, 128, 255])).await;
    assert!(pushed.ok);
    assert_eq!(pushed.cursor, 1);
    assert_eq!(
        SpaceStorage::get_space(&*p.edge_db.storage, p.space)
            .await
            .expect("edge space")
            .cursor,
        0
    );
    send_rpc_request(
        &mut client,
        "pull",
        "pull",
        &PullParams {
            spaces: vec![WsPullSpace {
                id: p.space.to_string(),
                since: 0,
                ucan: p.read(),
            }],
        },
    )
    .await;
    let begin: RpcChunkResponse<WsPullBeginData> = read_chunk_response(&mut client).await;
    assert_eq!(begin.name, "pull.begin");
    assert_eq!(begin.data.cursor, 1);
    let entry: RpcChunkResponse<WsPullRecordData> = read_chunk_response(&mut client).await;
    assert_eq!(entry.name, "pull.record");
    assert_eq!(entry.data.id, record.to_string());
    assert_eq!(entry.data.blob, Some(vec![0, 128, 255]));
    let commit: RpcChunkResponse<WsPullCommitData> = read_chunk_response(&mut client).await;
    assert_eq!(commit.data.count, 1);
    assert_eq!(
        read_result_response::<PullSummaryResult>(&mut client)
            .await
            .result
            .chunks,
        3
    );
    let conflict: PushRpcResult = rpc(&mut client, "push", &p.push(record, 0, b"stale")).await;
    assert!(!conflict.ok);
    assert_eq!(conflict.error, ERR_CODE_CONFLICT);
    assert_eq!(
        SpaceStorage::get_space(&*p.home_db.storage, p.space)
            .await
            .expect("home")
            .cursor,
        1
    );
    client.close(None).await.expect("close client");
    p.finish().await;
}

#[tokio::test]
async fn cut_link_releases_quotas_and_cached_fst_restores_notifications() {
    let Some(mut p) = Pair::new(limits()).await else {
        return;
    };
    let domain = p.link.addr.to_string();
    p.manager
        .subscribe(&domain, &p.link.url(), &[p.subscription()])
        .await
        .expect("subscribe");
    p.usage(1, 1).await;
    for _ in 0..3 {
        p.link.cut();
        p.usage(0, 0).await;
        p.manager
            .restore_subscriptions(&domain, &p.link.url())
            .await
            .expect("restore FST");
        p.usage(1, 1).await;
    }
    assert_eq!(p.link.accepted.load(Ordering::SeqCst), 4);
    let mut writer = p.peer().await;
    let pushed: PushRpcResult =
        rpc(&mut writer, "push", &p.push(Uuid::new_v4(), 0, b"remote")).await;
    assert!(pushed.ok);
    let (method, params) = tokio::time::timeout(Duration::from_secs(3), p.notifications.recv())
        .await
        .expect("notification deadline")
        .expect("notification");
    assert_eq!(method, "sync");
    let sync: WsSyncData = decode(&params);
    assert_eq!(sync.cursor, 1);
    assert_eq!(sync.records.len(), 1);
    writer.close(None).await.expect("close writer");
    p.usage(1, 1).await;
    p.finish().await;
}

#[tokio::test]
async fn duplicate_subscriptions_consume_one_slot_and_disconnect_releases_it() {
    let Some(p) = Pair::new(FederationQuotaLimits {
        max_spaces: 1,
        ..limits()
    })
    .await
    else {
        return;
    };
    let mut peer = p.peer().await;
    let requested = p.subscription();
    let result: SubscribeResult = rpc(
        &mut peer,
        "subscribe",
        &SubscribeParams {
            spaces: vec![requested.clone(), requested.clone()],
        },
    )
    .await;
    assert_eq!(result.spaces.len(), 2);
    assert!(result.errors.is_empty());
    p.usage(1, 1).await;
    let _: SubscribeResult = rpc(
        &mut peer,
        "subscribe",
        &SubscribeParams {
            spaces: vec![requested],
        },
    )
    .await;
    p.usage(1, 1).await;
    peer.close(None).await.expect("close peer");
    p.usage(0, 0).await;
    p.finish().await;
}

#[tokio::test]
async fn rejected_push_quota_preserves_database_and_connection_remains_usable() {
    let Some(p) = Pair::new(FederationQuotaLimits {
        max_records_per_hour: 1,
        ..limits()
    })
    .await
    else {
        return;
    };
    let mut peer = p.peer().await;
    let accepted: PushRpcResult =
        rpc(&mut peer, "push", &p.push(Uuid::new_v4(), 0, b"first")).await;
    assert!(accepted.ok);
    send_rpc_request(
        &mut peer,
        "quota",
        "push",
        &p.push(Uuid::new_v4(), 0, b"rejected"),
    )
    .await;
    assert_eq!(
        read_error_response(&mut peer).await.error.code,
        ERR_CODE_RATE_LIMITED
    );
    assert_eq!(
        SpaceStorage::get_space(&*p.home_db.storage, p.space)
            .await
            .expect("space")
            .cursor,
        1
    );
    assert_eq!(p.quota.peer_status(PEER).await.records_this_hour, 1);
    let subscribed: SubscribeResult = rpc(
        &mut peer,
        "subscribe",
        &SubscribeParams {
            spaces: vec![p.subscription()],
        },
    )
    .await;
    assert!(subscribed.errors.is_empty());
    peer.close(None).await.expect("close");
    p.usage(0, 0).await;
    p.finish().await;
}

#[tokio::test]
async fn fst_for_deleted_space_is_rejected_without_consuming_subscription_quota() {
    let Some(p) = Pair::new(limits()).await else {
        return;
    };
    let mut peer = p.peer().await;
    let subscribed: SubscribeResult = rpc(
        &mut peer,
        "subscribe",
        &SubscribeParams {
            spaces: vec![p.subscription()],
        },
    )
    .await;
    let token = subscribed.spaces[0].token.clone();
    assert!(!token.is_empty());
    peer.close(None).await.expect("close");
    p.usage(0, 0).await;
    sqlx::query("DELETE FROM spaces WHERE id=$1")
        .bind(p.space)
        .execute(p.home_db.storage.pool())
        .await
        .expect("delete space");
    let mut peer = p.peer().await;
    let result: SubscribeResult = rpc(
        &mut peer,
        "subscribe",
        &SubscribeParams {
            spaces: vec![WsSubscribeSpace {
                ucan: String::new(),
                token,
                ..p.subscription()
            }],
        },
    )
    .await;
    assert!(result.spaces.is_empty());
    assert_eq!(result.errors[0].error, ERR_CODE_NOT_FOUND);
    p.usage(1, 0).await;
    peer.close(None).await.expect("close");
    p.usage(0, 0).await;
    p.finish().await;
}

#[tokio::test]
async fn byte_quota_counts_wrapped_keys_and_rejection_does_not_consume_budget() {
    let Some(p) = Pair::new(FederationQuotaLimits {
        max_bytes_per_hour: 46,
        ..limits()
    })
    .await
    else {
        return;
    };
    let mut peer = p.peer().await;
    send_rpc_request(
        &mut peer,
        "over-budget",
        "push",
        &p.push(Uuid::new_v4(), 0, b"123"),
    )
    .await;
    assert_eq!(
        read_error_response(&mut peer).await.error.code,
        ERR_CODE_RATE_LIMITED
    );
    let status = p.quota.peer_status(PEER).await;
    assert_eq!(status.bytes_this_hour, 0);
    assert_eq!(status.records_this_hour, 0);
    let accepted: PushRpcResult = rpc(&mut peer, "push", &p.push(Uuid::new_v4(), 0, b"12")).await;
    assert!(accepted.ok);
    assert_eq!(p.quota.peer_status(PEER).await.bytes_this_hour, 46);
    peer.close(None).await.expect("close");
    p.usage(0, 0).await;
    p.finish().await;
}

#[tokio::test]
async fn subscribe_partial_errors_only_register_authorized_spaces() {
    let Some(p) = Pair::new(FederationQuotaLimits {
        max_spaces: 1,
        ..limits()
    })
    .await
    else {
        return;
    };
    let mut peer = p.peer().await;
    let valid = p.subscription();
    let result: SubscribeResult = rpc(
        &mut peer,
        "subscribe",
        &SubscribeParams {
            spaces: vec![
                WsSubscribeSpace {
                    id: "invalid-uuid".into(),
                    ..valid.clone()
                },
                WsSubscribeSpace {
                    id: Uuid::new_v4().to_string(),
                    ..valid.clone()
                },
                WsSubscribeSpace {
                    ucan: "invalid-token".into(),
                    ..valid.clone()
                },
                WsSubscribeSpace {
                    ucan: String::new(),
                    ..valid.clone()
                },
                valid,
            ],
        },
    )
    .await;
    assert_eq!(result.spaces.len(), 1);
    assert_eq!(
        result
            .errors
            .iter()
            .map(|e| e.error.as_str())
            .collect::<Vec<_>>(),
        [
            ERR_CODE_BAD_REQUEST,
            ERR_CODE_NOT_FOUND,
            ERR_CODE_FORBIDDEN,
            ERR_CODE_BAD_REQUEST
        ]
    );
    p.usage(1, 1).await;
    peer.close(None).await.expect("close");
    p.usage(0, 0).await;
    p.finish().await;
}

#[tokio::test]
async fn fst_is_bound_to_space_and_signing_peer_domain() {
    let Some(p) = Pair::new(limits()).await else {
        return;
    };
    let mut peer = p.peer().await;
    let keys = FederationTokenKeys::new(derive_fst_key(b"integration"));
    let wrong_space = keys.create_fst(Uuid::new_v4(), PEER, None).expect("token");
    let wrong_peer = keys
        .create_fst(p.space, "untrusted.example", None)
        .expect("token");
    for token in [wrong_space, wrong_peer] {
        let result: SubscribeResult = rpc(
            &mut peer,
            "subscribe",
            &SubscribeParams {
                spaces: vec![WsSubscribeSpace {
                    ucan: String::new(),
                    token,
                    ..p.subscription()
                }],
            },
        )
        .await;
        assert!(result.spaces.is_empty());
        assert_eq!(result.errors[0].error, ERR_CODE_FORBIDDEN);
    }
    p.usage(1, 0).await;
    peer.close(None).await.expect("close");
    p.usage(0, 0).await;
    p.finish().await;
}

#[tokio::test]
async fn fst_metadata_failure_is_internal_and_retry_can_subscribe() {
    let Some(p) = Pair::new(limits()).await else {
        return;
    };
    let token = FederationTokenKeys::new(derive_fst_key(b"integration"))
        .create_fst(p.space, PEER, None)
        .expect("token");
    let mut peer = p.peer().await;
    sqlx::query("ALTER TABLE spaces RENAME TO unavailable_spaces")
        .execute(p.home_db.storage.pool())
        .await
        .expect("inject database failure");
    let result: SubscribeResult = rpc(
        &mut peer,
        "subscribe",
        &SubscribeParams {
            spaces: vec![WsSubscribeSpace {
                ucan: String::new(),
                token: token.clone(),
                ..p.subscription()
            }],
        },
    )
    .await;
    sqlx::query("ALTER TABLE unavailable_spaces RENAME TO spaces")
        .execute(p.home_db.storage.pool())
        .await
        .expect("restore database");
    assert!(result.spaces.is_empty());
    assert_eq!(result.errors[0].error, ERR_CODE_INTERNAL);
    p.usage(1, 0).await;
    let result: SubscribeResult = rpc(
        &mut peer,
        "subscribe",
        &SubscribeParams {
            spaces: vec![WsSubscribeSpace {
                ucan: String::new(),
                token,
                ..p.subscription()
            }],
        },
    )
    .await;
    assert_eq!(result.spaces.len(), 1);
    p.usage(1, 1).await;
    peer.close(None).await.expect("close");
    p.usage(0, 0).await;
    p.finish().await;
}

#[tokio::test]
async fn dropped_peer_manager_closes_socket_and_releases_remote_quota() {
    let Some(p) = Pair::new(limits()).await else {
        return;
    };
    let manager = FederationPeerManager::new(KEY_ID, p.signing_key.clone());
    manager
        .subscribe(&p.link.addr.to_string(), &p.link.url(), &[p.subscription()])
        .await
        .expect("subscribe");
    p.usage(1, 1).await;
    drop(manager);
    p.usage(0, 0).await;
    p.finish().await;
}

#[tokio::test]
async fn edge_does_not_acknowledge_a_subscription_rejected_by_home() {
    let Some(p) = Pair::new(limits()).await else {
        return;
    };
    let read_ucan = p.read();
    betterbase_sync_storage::RevocationStorage::revoke_ucan(
        &*p.home_db.storage,
        p.space,
        &compute_ucan_cid(&read_ucan),
    )
    .await
    .expect("revoke at home");
    let mut client = p.client().await;
    let subscribed: SubscribeResult = rpc(
        &mut client,
        "subscribe",
        &SubscribeParams {
            spaces: vec![WsSubscribeSpace {
                ucan: read_ucan,
                ..p.subscription()
            }],
        },
    )
    .await;
    assert!(subscribed.spaces.is_empty());
    assert_eq!(subscribed.errors.len(), 1);
    assert_eq!(subscribed.errors[0].error, ERR_CODE_INTERNAL);
    p.usage(1, 0).await;
    client.close(None).await.expect("close client");
    p.finish().await;
}

#[tokio::test]
async fn rpc_quota_rejection_keeps_existing_peer_connection_and_subscription() {
    let Some(p) = Pair::new(FederationQuotaLimits {
        max_records_per_hour: 0,
        ..limits()
    })
    .await
    else {
        return;
    };
    let domain = p.link.addr.to_string();
    p.manager
        .subscribe(&domain, &p.link.url(), &[p.subscription()])
        .await
        .expect("subscribe");
    p.usage(1, 1).await;
    let result = p
        .manager
        .forward_push(
            &domain,
            &p.link.url(),
            &p.push(Uuid::new_v4(), 0, b"over quota"),
        )
        .await;
    assert!(
        matches!(result,Err(FederationPeerError::Rpc(ref error)) if error.code==ERR_CODE_RATE_LIMITED)
    );
    p.usage(1, 1).await;
    p.manager
        .restore_subscriptions(&domain, &p.link.url())
        .await
        .expect("still usable");
    assert_eq!(p.link.accepted.load(Ordering::SeqCst), 1);
    p.finish().await;
}

#[tokio::test]
async fn malformed_federation_rpc_returns_errors_and_keeps_socket_usable() {
    let Some(p) = Pair::new(limits()).await else {
        return;
    };
    let mut peer = p.peer().await;
    for method in ["push", "pull"] {
        send_rpc_request(
            &mut peer,
            "malformed",
            method,
            &serde_json::json!({"spaces":"not-an-array","changes":"not-an-array"}),
        )
        .await;
        assert_eq!(
            read_error_response(&mut peer).await.error.code,
            ERR_CODE_INVALID_PARAMS
        );
    }
    let pushed: PushRpcResult = rpc(&mut peer, "push", &p.push(Uuid::new_v4(), 0, b"valid")).await;
    assert!(pushed.ok);
    peer.close(None).await.expect("close");
    p.usage(0, 0).await;
    p.finish().await;
}

#[tokio::test]
async fn federation_push_rejections_never_advance_cursor() {
    let Some(p) = Pair::new(limits()).await else {
        return;
    };
    let mut peer = p.peer().await;
    let valid = p.push(Uuid::new_v4(), 0, b"encrypted");
    let personal = Uuid::new_v4();
    SpaceStorage::create_space(&*p.home_db.storage, personal, "personal", None)
        .await
        .expect("personal");
    let mut invalid_record = valid.clone();
    invalid_record.changes[0].id = "invalid-record".into();
    let cases = [
        (
            PushParams {
                space: "invalid-space".into(),
                ..valid.clone()
            },
            ERR_CODE_BAD_REQUEST,
        ),
        (
            PushParams {
                space: Uuid::new_v4().to_string(),
                ..valid.clone()
            },
            ERR_CODE_NOT_FOUND,
        ),
        (
            PushParams {
                ucan: p.read(),
                ..valid.clone()
            },
            ERR_CODE_FORBIDDEN,
        ),
        (
            PushParams {
                space: personal.to_string(),
                ..valid.clone()
            },
            ERR_CODE_FORBIDDEN,
        ),
        (invalid_record, ERR_CODE_BAD_REQUEST),
    ];
    for (params, code) in cases {
        let rejected: PushRpcResult = rpc(&mut peer, "push", &params).await;
        assert!(!rejected.ok);
        assert_eq!(rejected.error, code);
        assert_eq!(
            SpaceStorage::get_space(&*p.home_db.storage, p.space)
                .await
                .expect("space")
                .cursor,
            0
        );
    }
    sqlx::query("UPDATE spaces SET home_server = 'other.example' WHERE id=$1")
        .bind(p.space)
        .execute(p.home_db.storage.pool())
        .await
        .expect("remote space");
    let rejected: PushRpcResult = rpc(&mut peer, "push", &valid).await;
    assert_eq!(rejected.error, ERR_CODE_FORBIDDEN);
    sqlx::query("UPDATE spaces SET home_server = NULL WHERE id=$1")
        .bind(p.space)
        .execute(p.home_db.storage.pool())
        .await
        .expect("local space");
    sqlx::query("ALTER TABLE spaces RENAME TO unavailable_spaces")
        .execute(p.home_db.storage.pool())
        .await
        .expect("fail database");
    let rejected: PushRpcResult = rpc(&mut peer, "push", &valid).await;
    sqlx::query("ALTER TABLE unavailable_spaces RENAME TO spaces")
        .execute(p.home_db.storage.pool())
        .await
        .expect("restore database");
    assert!(!rejected.ok);
    assert_eq!(rejected.error, ERR_CODE_INTERNAL);
    let accepted: PushRpcResult = rpc(&mut peer, "push", &valid).await;
    assert!(accepted.ok);
    assert_eq!(accepted.cursor, 1);
    peer.close(None).await.expect("close");
    p.usage(0, 0).await;
    p.finish().await;
}

#[tokio::test]
async fn federation_pull_skips_invalid_or_unauthorized_spaces_without_leaking_records() {
    let Some(p) = Pair::new(limits()).await else {
        return;
    };
    let domain = p.link.addr.to_string();
    let pushed = p
        .manager
        .forward_push(
            &domain,
            &p.link.url(),
            &p.push(Uuid::new_v4(), 0, b"encrypted"),
        )
        .await
        .expect("push");
    assert!(pushed.ok);
    let authorized = WsPullSpace {
        id: p.space.to_string(),
        since: 0,
        ucan: p.read(),
    };
    let chunks = p
        .manager
        .pull(
            &domain,
            &p.link.url(),
            &[
                WsPullSpace {
                    id: "invalid-space".into(),
                    ..authorized.clone()
                },
                WsPullSpace {
                    id: Uuid::new_v4().to_string(),
                    ..authorized.clone()
                },
                WsPullSpace {
                    ucan: String::new(),
                    ..authorized.clone()
                },
                authorized,
            ],
        )
        .await
        .expect("pull");
    assert_eq!(
        chunks.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
        ["pull.begin", "pull.record", "pull.commit"]
    );
    let commit: WsPullCommitData = decode(&chunks[2].data);
    assert_eq!(commit.space, p.space.to_string());
    assert_eq!(commit.count, 1);
    p.finish().await;
}

#[tokio::test]
async fn failed_federation_pull_stream_has_no_commit_and_retry_recovers() {
    let Some(p) = Pair::new(limits()).await else {
        return;
    };
    let domain = p.link.addr.to_string();
    let pushed = p
        .manager
        .forward_push(
            &domain,
            &p.link.url(),
            &p.push(Uuid::new_v4(), 0, b"encrypted"),
        )
        .await
        .expect("push");
    assert!(pushed.ok);
    let requested = WsPullSpace {
        id: p.space.to_string(),
        since: 0,
        ucan: p.read(),
    };
    sqlx::query("ALTER TABLE records RENAME TO unavailable_records")
        .execute(p.home_db.storage.pool())
        .await
        .expect("fail stream query");
    let chunks = p
        .manager
        .pull(&domain, &p.link.url(), std::slice::from_ref(&requested))
        .await
        .expect("incomplete pull");
    sqlx::query("ALTER TABLE unavailable_records RENAME TO records")
        .execute(p.home_db.storage.pool())
        .await
        .expect("restore stream query");
    assert_eq!(
        chunks.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
        ["pull.begin"]
    );
    let chunks = p
        .manager
        .pull(&domain, &p.link.url(), &[requested])
        .await
        .expect("retry");
    assert_eq!(
        chunks.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
        ["pull.begin", "pull.record", "pull.commit"]
    );
    let commit: WsPullCommitData = decode(&chunks[2].data);
    assert_eq!(commit.cursor, 1);
    assert_eq!(commit.count, 1);
    p.finish().await;
}
