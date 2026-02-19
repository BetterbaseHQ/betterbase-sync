# Performance Benchmarks

This repo now includes a baseline benchmark set mirrored from the Go project for ballpark parity checks.

## Mirrored benchmark map

| Go benchmark | Rust benchmark |
|---|---|
| `BenchmarkValidateChainDepth1` | `validate_chain/depth/1` |
| `BenchmarkValidateChainDepth3` | `validate_chain/depth/3` |
| `BenchmarkValidateChainDepth8` | `validate_chain/depth/8` |
| `BenchmarkMultiBrokerBroadcastSync` | `multi_broker_broadcast_sync/fanout/*` |
| `BenchmarkMultiBrokerBroadcastMembership` | `multi_broker_broadcast_membership/fanout/*` |
| `BenchmarkRPCConnHandleMessageRequest` | `rpcconn_handle_message_request` |
| `BenchmarkRPCConnHandleMessageNotification` | `rpcconn_handle_message_notification` |
| `BenchmarkPostgresPushHot` | `postgres_push_hot` |
| `BenchmarkPostgresPullHot` | `postgres_pull_hot` |
| `BenchmarkPostgresPullHotFileHeavy` | `postgres_pull_hot_file_heavy` |

## Run commands

Auth benches:

```bash
cargo bench -p less-sync-auth --bench ucan
```

Realtime benches:

```bash
cargo bench -p less-sync-realtime --bench events
cargo bench -p less-sync-realtime --bench rpcconn
```

Storage benches (requires `DATABASE_URL`):

```bash
export DATABASE_URL='postgres://...'
cargo bench -p less-sync-storage --bench postgres
```

Run all mirrored benches:

```bash
cargo bench -p less-sync-auth --bench ucan && \
cargo bench -p less-sync-realtime --bench events && \
cargo bench -p less-sync-realtime --bench rpcconn && \
cargo bench -p less-sync-storage --bench postgres
```

## Notes

- Rust benches use Criterion; Go benches use `go test -bench`. Exact methodology differs, so compare trends and order-of-magnitude, not absolute values.
- Storage benches run in an isolated Postgres schema per benchmark process.
