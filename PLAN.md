# less-sync-rs Port Plan

## Scope
- Port `less-sync` (Go) to Rust with Tokio as the runtime for all async/server paths.
- Use the existing `less-sync` code and its local test suite as the primary compatibility oracle.
- Focus exclusively on local tests in this plan (external e2e exists but is intentionally out of scope here).

## Success Criteria
1. Rust server is behaviorally compatible with the Go server for all locally tested features.
2. Rust codebase is clear, modular, and maintainable enough to serve as the template for future Rust services.
3. Test rigor is at least as strong as today, with explicit coverage gates and no merge without tests.
4. Tokio concurrency model is used consistently across networking, background tasks, and async I/O.

## Baseline Inventory (Current Go Project)
- Test surface: `53` local test files, `467` tests, `20` benchmarks.
- Test distribution:
1. `server/*_test.go`: `235` tests (WebSocket/RPC/API/federation behavior).
2. `server/auth/*_test.go`: `94` tests (JWT, UCAN, did:key, sessions, HTTP signatures, federation tokens/JWKS).
3. `storage/*_test.go` + `storage/files/*_test.go`: `113` tests (Postgres semantics, file metadata/storage).
4. `protocol/*_test.go`: `20` tests (CBOR/JSON protocol roundtrips).
5. `spaceid/*_test.go`: `5` tests (deterministic ID vectors).
- Storage schema: `11` SQL migrations in `storage/migrations/`.
- Current local harness patterns:
1. Postgres via testcontainers (`postgres:18-alpine`), shared container per package via `TestMain`.
2. Real JWT/JWKS and UCAN test helpers in `internal/testutil`.
3. No DB mocks for core storage behavior.

## Architecture Audit (Do Not Inherit)
1. Avoid large mixed-responsibility modules:
- Current Go has very large files (`server/events.go`, `server/rpcconn.go`, `storage/postgres.go`).
- Rust target: small focused modules with clear ownership boundaries.
2. Avoid mutable process globals for runtime behavior:
- Current Go mutates package globals (for example max sizes).
- Rust target: immutable typed `Config` passed through dependency graph.
3. Avoid untyped context bags for auth/connection state:
- Current Go relies heavily on `context.WithValue`.
- Rust target: typed extractors and typed per-connection state objects.
4. Avoid panic-based internal control in runtime paths:
- Current Go has several panic guards in reusable components.
- Rust target: return typed errors; panic only for unrecoverable startup invariants.
5. Avoid generic map payloads in protocol internals:
- Current Go uses `map[string]any` in several frame/result paths.
- Rust target: strongly typed frame/result structs and enums.
6. Avoid hard coupling of federation and core sync paths:
- Rust target: federation module isolated behind explicit interfaces and feature flags.

## Non-Negotiable Behavioral Contracts To Preserve
1. WebSocket protocol:
- Subprotocol `less-rpc-v1`.
- First frame must be `auth` notification within timeout.
- Close-code behavior for auth/protocol/rate/slow-consumer paths.
- Keepalive and bounded buffering/backpressure semantics.
2. Authorization model:
- JWT validation via per-issuer JWKS.
- Personal-space deterministic IDs and auto-create semantics.
- Shared-space UCAN chain validation and revocation checks.
3. Data model and cursor semantics:
- Unified cursor ordering across records/members/files.
- Push conflict behavior and tombstone/file cleanup semantics.
- Epoch/rewrap invariants and DEK handling rules.
4. API contracts:
- RPC method names, frame shapes, and error codes.
- HTTP file endpoint header contracts (`X-Wrapped-DEK`, `X-Record-ID`, scopes).

## Target Rust Architecture

### Workspace layout
```text
less-sync-rs/
  Cargo.toml                    # workspace + shared lint/tool config
  crates/
    core/                       # protocol types, ids, validation, shared errors
    auth/                       # JWT/JWKS, UCAN, did:key, session/FST, HTTPSig
    storage/                    # storage traits + sqlx Postgres adapter + migrations
    realtime/                   # WS transport, RPC conn state machine, broker/presence
    api/                        # HTTP middleware/routes + handler adapters
    app/                        # composition root, config loading, task supervision
  bins/
    server/                     # runtime bootstrap + graceful shutdown
    migrate/                    # migration CLI
    federation-keygen/          # federation key bootstrap CLI
```

### Organization rules (ideal-state guardrails)
1. Do not mirror Go package boundaries 1:1.
2. Keep core crates runtime-agnostic where possible (`core`, most of `auth` parsing/validation logic).
3. Keep Tokio and networking details confined to `realtime`/`api`/`app`.
4. Keep file size targets strict:
- target <= 300 lines per source file
- hard review threshold at 500 lines
5. Define one boundary module per direction:
- inbound mapping (HTTP/WS -> domain commands)
- outbound mapping (domain results/errors -> protocol responses)
6. Keep federation in separate modules and behind `federation` feature flags until parity is complete.

### Tokio-first stack (recommended)
1. `tokio` for runtime, tasks, channels, timers.
2. `axum`/`hyper` for HTTP routes and middleware.
3. `tokio-tungstenite` (or equivalent low-level WS control) for strict WS frame handling.
4. `sqlx` for Postgres (`query!`/typed row mapping).
5. `tracing` + `tracing-subscriber` for structured logs.
6. `thiserror` for domain errors and `anyhow` only at binary boundaries.
7. `minicbor` (or equally strict CBOR crate) with explicit decode limits.

## Layered Port Roadmap

### Phase 0: Foundation and quality gates
1. Create Cargo workspace and crate skeleton above.
2. Add CI/local gates:
- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features`
3. Add baseline lint policy:
- `#![forbid(unsafe_code)]` by default.
- deny `unwrap`/`expect` outside tests.
- explicit `Send + Sync` constraints on shared async state.
4. Build `test-support` utilities (Postgres container manager, JWT/JWKS helpers, WS test helpers).
5. Add architecture conformance checks:
- deny use of `std::sync::Mutex` in async request paths (prefer Tokio primitives or lock-free patterns where needed)
- deny direct `panic!` in non-test library code via lint policy/review gate
- enforce crate visibility discipline (`pub(crate)` by default)

Exit criteria:
- Workspace compiles, tooling is green, empty scaffolds testable.

### Phase 1: Pure protocol and deterministic primitives
1. Port `spaceid` logic and vectors first.
2. Port `protocol` types/constants/error codes and CBOR/JSON roundtrip behavior.
3. Port validation helpers (record IDs, file IDs, size limits).

Exit criteria:
- Rust equivalents of `spaceid/*_test.go` and `protocol/*_test.go` pass.

### Phase 2: Auth and crypto domain
1. JWT multi-issuer validator + JWKS caching semantics.
2. UCAN parse/chain validation with depth/attenuation/revocation logic.
3. did:key encode/decode and compressed P-256 handling.
4. Session token and federation token/HTTP signature primitives.

Exit criteria:
- Rust equivalents of `server/auth/*_test.go` pass.

### Phase 3: Storage contract and Postgres implementation
1. Define Rust `Storage` trait mirroring current contract.
2. Reuse existing SQL migration files and preserve schema compatibility.
3. Implement Postgres storage methods with transaction isolation matching Go behavior.
4. Implement file metadata, invitations, rate limits, revocations, epoch/DEK, federation key persistence.
5. Port storage race/concurrency tests.

Exit criteria:
- Rust equivalents of `storage/*_test.go` and `storage/files/*_test.go` pass.

### Phase 4: Transport core (RPC + WebSocket + broker)
1. Implement RPC frame parsing/dispatch, chunk streaming, pending-call tracking.
2. Implement WebSocket connection lifecycle:
- auth-first handshake
- keepalive
- read limits
- slow-consumer handling
3. Implement broker fanout, connection limits, presence/events, cleanup loops.

Exit criteria:
- Rust equivalents of `server/rpcconn_test.go`, `server/wsconn_test.go`, `server/ws_protocol_test.go`, and broker-related tests pass.

### Phase 5: Core server features (non-federation)
1. Route wiring and middleware.
2. RPC handlers:
- `subscribe`, `push`, `pull`, `token.refresh`
- `space.create`
- `membership.*`
- `invitation.*`
- `epoch.*`
- `deks.*`
- `presence.*`, `event.send`
3. HTTP file handlers (`PUT/GET/HEAD`) with exact scope/header behavior.
4. Background jobs (`StartPurge`, presence cleanup), graceful shutdown.

Exit criteria:
- Rust equivalents of non-federation server tests pass (`server/ws_test.go`, `server/rpc_*_test.go`, `server/files_test.go`, `server/server_test.go`, `server/middleware_test.go`).

### Phase 6: Federation feature set
1. Federation WS auth (HTTP signatures + peer key lookup).
2. Federation RPC handlers and forwarding paths.
3. Peer manager, trust store, quotas, federation HTTP endpoints.
4. Federation key bootstrapping and JWKS publication.

Exit criteria:
- Rust equivalents of federation tests pass (`server/federation*_test.go`).

### Phase 7: Binaries, performance, and polish
1. Implement binaries matching Go commands:
- `server`
- `migrate`
- `federation-keygen`
- perf entrypoints (if retained)
2. Port/replace benchmark coverage for key hot paths.
3. Final API/documentation cleanup.

Exit criteria:
- Rust binary behavior and benchmark harnesses are functional locally.

## Test Strategy and Gates

### Porting strategy
1. Treat existing Go tests as executable specs; port them module by module.
2. Preserve test names and scenario intent where practical for traceability.
3. Prefer integration tests for behavior and small unit tests for pure logic.

### Coverage gates
1. Use `cargo llvm-cov` in CI.
2. Suggested minimums:
- `protocol`, `spaceid`, `auth`: >= `90%`
- `storage`, `app/rpc/broker`: >= `85%`
- federation modules: >= `80%`
3. No new public behavior without at least one failing-then-passing test.

### Runtime test requirements
1. Postgres container required for storage/server integration tests.
2. MinIO container required for S3 file backend tests.
3. Test helpers should keep same ergonomics as current Go `internal/testutil`.

## Rust Best-Practice Standards (Template for Future Projects)
1. Clear crate boundaries with narrow public APIs.
2. Strong typing for IDs and protocol enums (avoid stringly-typed internals).
3. Structured error enums per crate; avoid opaque error strings in core logic.
4. Zero shared mutable state without synchronization strategy and ownership clarity.
5. Bounded channels and explicit backpressure/cancellation in every long-lived async path.
6. `tracing` spans on request, connection, and storage transaction boundaries.
7. Keep migrations and storage queries explicit and reviewable.
8. Keep unsafe forbidden unless a documented, benchmarked justification exists.

## Delivery Plan
1. Land in small, reviewable PRs by phase.
2. Each phase must be independently green on lint + tests before continuing.
3. Federation is intentionally later-phase to avoid blocking core sync correctness.
4. Final cutover requires all local Rust parity tests passing and Go parity checks complete.

## Commit Discipline
1. Commit as we go:
- Do not batch large multi-phase changes into one commit.
- Make small, coherent commits that each leave the tree in a valid state.
2. No milestone cruft in commit subjects:
- Do not include labels like `Phase 1`, `Milestone`, `Step N`, `WIP`, or `checkpoint`.
- Subject lines must describe the concrete behavior or code change.
3. Subject line rules:
- Imperative mood (`Add`, `Refactor`, `Fix`, `Enforce`, `Port`).
- Clean and descriptive, scoped to what changed.
4. Message body rules:
- Brief bullets for what changed and why when context is useful.
- Avoid implementation noise and progress narration.
5. Preferred examples:
- `Port UCAN chain validation with depth and attenuation checks`
- `Add websocket auth-first handshake timeout and close-code tests`
- `Refactor broker presence cleanup into bounded async tasks`
6. Avoid examples:
- `Phase 2 milestone progress`
- `Milestone checkpoint`
- `WIP port work`
