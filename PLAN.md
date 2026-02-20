# less-sync-rs Improvement Plan

The port is complete. This plan is about making the codebase excellent.

## 1. Split the Storage Trait

The `Storage` trait has 40+ methods spanning every domain. Split into focused, composable traits so handlers bound only on what they need.

### Target traits

```
SpaceStorage       — get_space, create_space, get_or_create_space, update_space_metadata
RecordStorage      — push, pull, stream_pull, record_exists, delete_records
FileStorage        — record_file, get_file_metadata, file_exists, get_file_deks, rewrap_file_deks, delete_files_for_records
MembershipStorage  — append_member, list_members, get_membership_since
InvitationStorage  — create_invitation, get_invitation, list_invitations, delete_invitation
EpochStorage       — advance_epoch, complete_rewrap, get_epoch_state
RevocationStorage  — revoke_ucan, is_revoked
RateLimitStorage   — count_recent_actions, record_action
FederationStorage  — federation key lifecycle methods
```

### Unified supertrait for convenience

```rust
pub trait Storage:
    SpaceStorage + RecordStorage + FileStorage + MembershipStorage +
    InvitationStorage + EpochStorage + RevocationStorage +
    RateLimitStorage + FederationStorage {}

impl<T> Storage for T where T:
    SpaceStorage + RecordStorage + FileStorage + MembershipStorage +
    InvitationStorage + EpochStorage + RevocationStorage +
    RateLimitStorage + FederationStorage {}
```

`PostgresStorage` implements all sub-traits. The blanket impl means it automatically satisfies `Storage`. Code that needs everything can still bound on `Storage`.

## 2. Split postgres.rs into Modules

Currently one 4000+ line file. Mirror the trait split:

```
storage/
├── lib.rs                # Trait definitions, error types, common types
├── postgres/
│   ├── mod.rs            # PostgresStorage struct, pool, migration runner
│   ├── spaces.rs         # SpaceStorage impl
│   ├── records.rs        # RecordStorage impl
│   ├── files.rs          # FileStorage impl
│   ├── membership.rs     # MembershipStorage impl
│   ├── invitations.rs    # InvitationStorage impl
│   ├── epochs.rs         # EpochStorage impl
│   ├── revocation.rs     # RevocationStorage impl
│   ├── rate_limit.rs     # RateLimitStorage impl
│   └── federation.rs     # FederationStorage impl
```

Each file: 200-400 lines. Tests live next to the impl they cover.

## 3. Split ws/tests.rs and Extract Test Helpers

6,385 lines in one test file. Split by feature area and extract shared infrastructure.

### Test helper module

```
api/src/ws/
├── test_support/
│   ├── mod.rs            # Re-exports
│   ├── server.rs         # spawn_server, ServerHandle
│   ├── stubs.rs          # StubSyncStorage, StubValidator, StubHealth
│   ├── frames.rs         # send_rpc_request, read_result_response, etc.
│   └── builders.rs       # base_state, with_federation_auth, etc.
```

### Split tests by domain

```
api/src/ws/tests/
├── auth.rs               # Auth handshake, token refresh, expiry
├── push_pull.rs          # Push, pull, subscribe, cursor semantics
├── membership.rs         # Membership append, list, revoke
├── invitation.rs         # Invitation CRUD
├── epoch.rs              # Epoch begin, complete, DEK rewrap
├── files.rs              # File DEK get/rewrap via WS
├── federation.rs         # Federation subscribe, push, pull, quotas
├── presence.rs           # Presence join, leave, events
└── protocol.rs           # Frame parsing, keepalive, close codes
```

When `StubSyncStorage` is split along the trait boundaries (phase 1), each stub becomes 3-5 fields instead of 20+.

## 4. Automated PostgreSQL for Tests

Storage tests currently skip when `DATABASE_URL` isn't set. Fix this so `cargo test` works on any machine with Docker.

### Approach: testcontainers-rs

Add a dev-dependency on `testcontainers` with the Postgres module. Create a shared test harness:

```rust
// crates/storage/src/test_support.rs
pub async fn test_database() -> (PostgresStorage, Container) {
    // If DATABASE_URL is set, use it (CI with a service container)
    // Otherwise, start postgres:18-alpine via testcontainers
    // Run migrations
    // Return storage + container handle (container drops when test ends)
}
```

### Container reuse

Use `testcontainers`' `reuse` feature so the container persists across test runs during local development. First run: ~2s startup. Subsequent runs: instant.

### Per-test isolation

Each test gets its own schema (already the pattern in existing tests). No test pollution, full parallelism.

### Benefits

- `cargo test` works anywhere Docker runs — no manual Postgres setup
- CI never skips storage tests
- Tests use real SQL, real constraints, real query plans
- No in-memory fakes that drift from real Postgres behavior

## 5. Preserve Error Context

Replace `.map_err(|e| StorageError::Database(e.to_string()))` with proper error chains.

### Use thiserror with #[source]

```rust
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("space not found")]
    SpaceNotFound,
    #[error("database error")]
    Database(#[source] sqlx::Error),
    #[error("invalid wrapped DEK")]
    InvalidWrappedDek,
    // ...
}
```

`tracing::error!(%err)` gives the full chain. Pattern matching still works at the domain level. Debugging a constraint violation at 3am becomes possible.

### Add structured tracing spans to RPC handlers

```rust
async fn handle_push(/* ... */) {
    let _span = tracing::info_span!("rpc", method = "push", %space_id).entered();
    // ...
}
```

Correlate a slow push with its storage query. See which space is hot. Trace a request end-to-end.

## 6. Property-Based Tests

Add `proptest` for protocol invariants that are hard to cover exhaustively by hand.

### Candidates

- **CBOR round-trips**: Arbitrary RPC frames encode then decode to the same value
- **Cursor ordering**: Push N records in any order, pull returns monotonically increasing cursors
- **Push idempotency**: Push the same changes twice, second push doesn't advance cursor
- **UCAN chain validation**: Arbitrary valid chains pass; chains with any single invalid link fail
- **Membership hash chain**: Arbitrary append sequence produces valid chain; any mutation breaks it

### Where they live

Property tests go alongside unit tests in the same modules. They're just another way to exercise the same code — but they find the edge cases you don't think to write by hand.

## 7. Observability

### Metrics

```
rpc.requests{method}           — counter per RPC method
rpc.duration_ms{method}        — histogram per RPC method
ws.connections                 — gauge of active WebSocket connections
broker.spaces_watched          — gauge of spaces with subscribers
storage.push.records           — counter of records pushed
storage.pull.records           — counter of records pulled
federation.connections{peer}   — gauge per federation peer
```

### Health check

Expand beyond "can I reach Postgres" to include:
- Database pool utilization
- Broker subscriber count
- Federation peer connection status

When a client reports "sync is slow," you want to see: is it push latency? Pull latency? Broker fanout? Connection churn?

## 8. Split Federation into Its Own Crate

`crates/api` currently contains three different network boundaries: inbound WS, inbound HTTP, and outbound WS (federation client). The federation client initiates connections to peers — it's fundamentally different from request handling.

### Target structure

```
crates/
├── core/          # Protocol types (unchanged)
├── auth/          # Identity & authz (unchanged)
├── storage/       # Persistence (split per phase 2)
├── realtime/      # Pub/sub broker (unchanged)
├── api/           # Inbound: WS handlers + HTTP file handlers
├── federation/    # Outbound: peer manager, forwarding, quota, HTTP metadata
└── app/           # Wiring & config (unchanged)
```

Lower priority — do when federation is actively being worked on.

## 9. Graceful Shutdown

1. Stop accepting new connections
2. Stop accepting new WebSocket upgrades
3. Wait for in-flight RPC requests to complete (with timeout)
4. Send close frames to all connected clients
5. Drain the broker
6. Close the database pool

Axum supports this via `axum::serve(...).with_graceful_shutdown(signal)`. The broker needs a `drain()` method. This is the difference between "works" and "safe to deploy with zero-downtime rolling updates."

---

## Execution Order

| Phase | Work | Why this order |
|-------|------|----------------|
| **1** | Split Storage trait + postgres.rs | Structural foundation — everything else gets easier |
| **2** | Split ws/tests.rs + extract test helpers | Tests are documentation — make them findable |
| **3** | Automated Postgres via testcontainers | `cargo test` works everywhere, no tests skipped |
| **4** | Error context (thiserror + tracing spans) | Debug-ability is a feature |
| **5** | Property-based tests | Find the bugs you didn't think to look for |
| **6** | Observability (metrics + health) | Can't improve what you can't measure |
| **7** | Split federation into its own crate | Cleaner boundaries, do when touching federation |
| **8** | Graceful shutdown | Last mile to production-grade |
