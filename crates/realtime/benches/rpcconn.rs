use criterion::{black_box, criterion_group, criterion_main, Criterion};
use less_sync_core::protocol::{RPC_NOTIFICATION, RPC_REQUEST};
use less_sync_realtime::ws::parse_client_binary_frame;

fn bench_handle_message_request(c: &mut Criterion) {
    let frame = serde_cbor::to_vec(&serde_json::json!({
        "type": RPC_REQUEST,
        "id": "req-1",
        "method": "subscribe",
        "params": {
            "spaces": ["11111111-1111-1111-1111-111111111111"]
        }
    }))
    .expect("encode request frame");

    c.bench_function("rpcconn_handle_message_request", |b| {
        b.iter(|| {
            let parsed = parse_client_binary_frame(black_box(&frame)).expect("parse request");
            black_box(parsed);
        });
    });
}

fn bench_handle_message_notification(c: &mut Criterion) {
    let frame = serde_cbor::to_vec(&serde_json::json!({
        "type": RPC_NOTIFICATION,
        "method": "presence.set",
        "params": {
            "space": "11111111-1111-1111-1111-111111111111",
            "payload": [1, 2, 3]
        }
    }))
    .expect("encode notification frame");

    c.bench_function("rpcconn_handle_message_notification", |b| {
        b.iter(|| {
            let parsed = parse_client_binary_frame(black_box(&frame)).expect("parse notification");
            black_box(parsed);
        });
    });
}

criterion_group!(
    benches,
    bench_handle_message_request,
    bench_handle_message_notification
);
criterion_main!(benches);
