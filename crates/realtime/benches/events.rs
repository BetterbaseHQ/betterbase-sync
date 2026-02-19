use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use less_sync_core::protocol::{Change, RPC_NOTIFICATION};
use less_sync_realtime::broker::{BrokerConfig, MultiBroker, Subscriber};

const SPACE_ID: &str = "11111111-1111-1111-1111-111111111111";

struct BenchSubscriber {
    exclude_id: String,
    mailbox_id: String,
    bytes_seen: AtomicUsize,
}

impl BenchSubscriber {
    fn new(index: usize) -> Self {
        Self {
            exclude_id: format!("sub-{index}"),
            mailbox_id: format!("mailbox-{index}"),
            bytes_seen: AtomicUsize::new(0),
        }
    }
}

impl Subscriber for BenchSubscriber {
    fn send(&self, payload: Arc<[u8]>) -> bool {
        self.bytes_seen.fetch_add(payload.len(), Ordering::Relaxed);
        true
    }

    fn exclude_id(&self) -> &str {
        &self.exclude_id
    }

    fn mailbox_id(&self) -> &str {
        &self.mailbox_id
    }

    fn is_closed(&self) -> bool {
        false
    }
}

fn bench_broadcast_sync(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build runtime");
    let mut group = c.benchmark_group("multi_broker_broadcast_sync");

    for fanout in [10_usize, 100, 1_000] {
        let broker = Arc::new(MultiBroker::new(BrokerConfig::default()));
        runtime.block_on(async {
            for index in 0..fanout {
                let subscriber: Arc<dyn Subscriber> = Arc::new(BenchSubscriber::new(index));
                broker
                    .register_subscriber(subscriber, &[SPACE_ID.to_owned()])
                    .await
                    .expect("register benchmark subscriber");
            }
        });

        let payload = sync_payload();
        group.bench_with_input(BenchmarkId::new("fanout", fanout), &fanout, |b, _| {
            b.to_async(&runtime).iter(|| {
                let broker = Arc::clone(&broker);
                let payload = payload.clone();
                async move {
                    let delivered = broker.broadcast_space(SPACE_ID, "", &payload).await;
                    black_box(delivered);
                }
            });
        });
    }

    group.finish();
}

fn bench_broadcast_membership(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build runtime");
    let mut group = c.benchmark_group("multi_broker_broadcast_membership");

    for fanout in [10_usize, 100, 1_000] {
        let broker = Arc::new(MultiBroker::new(BrokerConfig::default()));
        runtime.block_on(async {
            for index in 0..fanout {
                let subscriber: Arc<dyn Subscriber> = Arc::new(BenchSubscriber::new(index));
                broker
                    .register_subscriber(subscriber, &[SPACE_ID.to_owned()])
                    .await
                    .expect("register benchmark subscriber");
            }
        });

        let payload = membership_payload();
        group.bench_with_input(BenchmarkId::new("fanout", fanout), &fanout, |b, _| {
            b.to_async(&runtime).iter(|| {
                let broker = Arc::clone(&broker);
                let payload = payload.clone();
                async move {
                    let delivered = broker.broadcast_space(SPACE_ID, "", &payload).await;
                    black_box(delivered);
                }
            });
        });
    }

    group.finish();
}

fn sync_payload() -> Vec<u8> {
    let payload = serde_json::json!({
        "type": RPC_NOTIFICATION,
        "method": "sync",
        "params": {
            "space": SPACE_ID,
            "prev": 99,
            "cursor": 100,
            "changes": [
                Change {
                    id: "019400e8-7b5d-7000-8000-000000000001".to_owned(),
                    blob: Some(b"blob-1".to_vec()),
                    cursor: 100,
                    wrapped_dek: None,
                    deleted: false,
                },
                Change {
                    id: "019400e8-7b5d-7000-8000-000000000002".to_owned(),
                    blob: Some(b"blob-2".to_vec()),
                    cursor: 100,
                    wrapped_dek: None,
                    deleted: false,
                }
            ]
        }
    });
    serde_cbor::to_vec(&payload).expect("encode sync payload")
}

fn membership_payload() -> Vec<u8> {
    let payload = serde_json::json!({
        "type": RPC_NOTIFICATION,
        "method": "membership",
        "params": {
            "space": SPACE_ID,
            "cursor": 100,
            "entries": [
                {
                    "chain_seq": 1,
                    "entry_hash": [104, 97, 115, 104],
                    "payload": [112, 97, 121, 108, 111, 97, 100]
                }
            ]
        }
    });
    serde_cbor::to_vec(&payload).expect("encode membership payload")
}

criterion_group!(benches, bench_broadcast_sync, bench_broadcast_membership);
criterion_main!(benches);
