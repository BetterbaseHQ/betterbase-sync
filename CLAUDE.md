# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

betterbase-sync is the encrypted blob sync service for the Less platform, ported from Go (betterbase-sync). The server stores and syncs encrypted blobs via WebSocket RPC (CBOR) and HTTP. Encryption happens client-side — the server never sees plaintext.

## Commands

```bash
just check          # fmt + clippy + test (the standard workflow)
just test           # cargo test (DB tests auto-skip without DATABASE_URL)
just test-db        # spins up PostgreSQL in Docker, runs full suite, tears down
just test-v         # tests with --nocapture
just bench-db       # storage benchmarks against real PostgreSQL
just lint           # cargo clippy --workspace -- -D warnings
just fmt            # cargo fmt --all

# Run a single test
cargo test -p betterbase-sync-auth test_name
cargo test -p betterbase-sync-storage test_name

# Database tests with a running container
just db-start       # start test PostgreSQL (port 15432)
DATABASE_URL="postgres://sync:sync@localhost:15432/sync_test?sslmode=disable" cargo test -p betterbase-sync-storage test_name
just db-down        # remove container
```

## Architecture

### Crate dependency graph

```
core          ← no internal deps; protocol types, space ID derivation, validation
auth          → core; JWT/JWKS, UCAN chains, DID keys, HTTP signatures, sessions
storage       → core; PostgreSQL traits + impl (spaces, records, files, membership, epochs)
realtime      → core; WebSocket broker for push notifications
api           → core, auth, storage, realtime; Axum HTTP/WS handlers, federation
app           → all crates; server config, startup, federation runtime
```

Binaries: `bins/server` (entry point), `bins/migrate` (standalone migrations), `bins/federation-keygen` (Ed25519 key gen).

### Storage trait design

Storage is split into focused traits (`SpaceStorage`, `RecordStorage`, `FileStorage`, `MembershipStorage`, `EpochStorage`, `RevocationStorage`, `InvitationStorage`, `RateLimitStorage`, `FederationStorage`) composed via a blanket-impl supertrait `Storage`. `PostgresStorage` implements all of them. Implementation files live in `crates/storage/src/postgres/` split by domain.

Large pulls use streaming (`PullStream` with `mpsc::Receiver`) to avoid loading full result sets into memory.

### WebSocket RPC

Subprotocol `less-rpc-v1`. CBOR-encoded frames with discriminator: request (0), response (1), notification (2), chunk (3). The first message on a new connection must be an `auth` notification carrying a JWT. Error codes are strings (`invalid_params`, `forbidden`, `conflict`, `key_generation_stale`). Custom close codes: 4000–4007.

### API routes

`/health`, `/.well-known/jwks.json` (public), `/api/v1/ws` (client WebSocket, JWT auth in-band), `/api/v1/federation/ws` (peer WebSocket, HTTP signature auth), `/api/v1/federation/trusted`, `/api/v1/federation/status/{domain}`, `/api/v1/spaces/{space_id}/files/{id}` (PUT/GET/HEAD). All responses carry `X-Protocol-Version: 1`.

### ApiState builder

Feature composition via `ApiState::new(health).with_websocket(v).with_sync_storage(s).with_realtime_broker(b)...`. Optional features (federation, files, presence) are `Option<T>` — the router conditionally registers routes based on what's configured.

## Key Conventions

- **`#![forbid(unsafe_code)]`** on every crate — maintain this.
- **Error types**: domain-specific enums with `thiserror`, `Clone + PartialEq + Eq` for testability. Map external errors early; never leak sqlx/reqwest types.
- **CBOR serialization**: `minicbor-serde`. Use `serde_bytes` for byte fields, `skip_serializing_if` for optional/zero-value fields, and the `option_bytes` helper in `core::protocol::ws` for `Option<Vec<u8>>`.
- **Test isolation**: each DB test gets its own PostgreSQL schema (`test_{uuid}`), auto-created by `test_support::test_storage()`. Tests return `None` gracefully when `DATABASE_URL` is unset.
- **API tests**: use stub trait impls (`StubHealth`, `StubValidator`) + `tower::ServiceExt::oneshot` to test routes without a running server.
- **Async**: `#[tokio::test]` for async tests, `async_trait` for trait methods.

## Environment Variables

Required: `DATABASE_URL`, `TRUSTED_ISSUERS` (space-separated issuer URLs or `issuer=jwks_url` pairs).

Optional: `LISTEN_ADDR` (default `0.0.0.0:5379`), `AUDIENCES`, `IDENTITY_HASH_KEY` (base64, 32 bytes), `SPACE_SESSION_SECRET` (base64, 32 bytes), `FILE_STORAGE_BACKEND` (`local`/`s3`), `FILE_STORAGE_PATH`.

Federation: `FEDERATION_TRUSTED_DOMAINS`, `FEDERATION_TRUSTED_KEYS`, `FEDERATION_FST_SECRET`, `FEDERATION_FST_PREVIOUS_SECRET`, plus quota limits (`FEDERATION_MAX_SPACES`, `FEDERATION_MAX_RECORDS_PER_HOUR`, etc.).

## Immutable v1 Contracts

Frozen — changes require a versioned migration:
- All `/api/v1/` route paths, `less-rpc-v1` subprotocol, RPC frame types/error codes, WebSocket close codes 4000–4007
- Encryption envelope v4: `[0x04][IV:12][ciphertext+tag]`
- Space ID derivation: `UUID5(LESS_NS, "{issuer}\0{user_id}\0{client_id}")`
- `X-Protocol-Version: 1` response header
