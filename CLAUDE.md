# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

betterbase-sync is the encrypted blob sync service for the Betterbase platform. It stores and syncs encrypted blobs via WebSocket RPC (CBOR) and HTTP. Encryption happens client-side -- the server never sees plaintext. Supports cursor-based sync, file storage, epoch-based forward secrecy, membership chains, invitations, federation, and real-time push notifications.

Part of the [betterbase-dev](https://github.com/BetterbaseHQ/betterbase-dev) orchestration repo.

## Commands

```bash
just check          # fmt + clippy + test (standard workflow check)
just test           # cargo test (DB tests auto-skip without DATABASE_URL)
just test-db        # Spin up Postgres container, run full suite, tear down
just test-v         # Tests with --nocapture
just bench          # cargo bench --workspace
just bench-db       # Storage benchmarks against real PostgreSQL
just lint           # cargo clippy --workspace -- -D warnings
just fmt            # cargo fmt --all
just build          # cargo build --workspace
just db-start       # Start test PostgreSQL on port 15432
just db-down        # Stop and remove test container
just db-shell       # psql into test database
```

Run a single test:
```bash
cargo test -p betterbase-sync-auth test_name
cargo test -p betterbase-sync-storage test_name
```

Database tests with a running container:
```bash
just db-start
DATABASE_URL="postgres://sync:sync@localhost:15432/sync_test?sslmode=disable" cargo test -p betterbase-sync-storage test_name
just db-down
```

## Workspace Structure

**Binaries** (`bins/`):
- `server` -- Main HTTP/WebSocket server (Axum). Entry point calls `app::run()`.
- `migrate` -- Standalone database migration runner.
- `federation-keygen` -- Ed25519 key pair generator for federation.

**Library crates** (`crates/`), in dependency order:

```
core          <- no internal deps; protocol types, space ID derivation, validation
auth          -> core; JWT/JWKS, UCAN chains, DID keys, HTTP signatures, sessions, federation tokens
storage       -> core; PostgreSQL traits + impl (spaces, records, files, membership, epochs, federation)
realtime      -> core; WebSocket broker for push notifications (MultiBroker)
api           -> core, auth, storage, realtime; Axum HTTP/WS handlers, federation endpoints, file endpoints
app           -> all crates; server config (env-based), startup, federation runtime, presence cleanup
```

## Architecture

### WebSocket RPC

Subprotocol `betterbase-rpc-v1`. CBOR-encoded frames with discriminator: request (0), response (1), notification (2), chunk (3). The first message on a new connection must be an `auth` notification carrying a JWT. Error codes are strings (`invalid_params`, `forbidden`, `conflict`, `key_generation_stale`). Custom close codes: 4000-4007.

### Storage Layer

Trait-based with focused domain traits composed via blanket-impl `Storage` supertrait:

| Trait | Responsibility |
|---|---|
| `SpaceStorage` | Space CRUD, ping/health |
| `RecordStorage` | Push/pull records, streaming pulls (`PullStream` with mpsc channel for O(1) memory) |
| `FileStorage` | File metadata, DEK management, file deletion |
| `RevocationStorage` | UCAN revocation by CID |
| `InvitationStorage` | Mailbox invitations with expiry |
| `MembershipStorage` | Hash-chained membership log |
| `EpochStorage` | Forward secrecy epochs, DEK rewrapping |
| `RateLimitStorage` | Action counting and cleanup |
| `FederationStorage` | Federation keys, space home servers |

`PostgresStorage` implements all traits. Implementation files are split by domain in `crates/storage/src/postgres/`.

### ApiState Builder

Feature composition via builder pattern: `ApiState::new(health).with_websocket(v).with_sync_storage(s).with_realtime_broker(b)...`. Optional features (federation, files, presence) are `Option<T>` -- the router conditionally registers routes based on what is configured.

### Federation

HTTP Signatures (Ed25519) for peer authentication. Federation Subscribe Tokens (FST) for WebSocket auth. Trusted domains with quota tracking (connections, spaces, records/hour, bytes/hour, invitations/hour).

### File Storage

Pluggable via `object_store` crate. Backends: local filesystem, S3-compatible. Files are encrypted client-side; server stores wrapped DEKs alongside metadata.

## API Routes

All routes are immutable v1 contracts. Every response includes `X-Protocol-Version: 1`.

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | Public | Health check (includes federation summary if enabled) |
| GET | `/.well-known/jwks.json` | Public | Federation JWKS |
| GET | `/api/v1/ws` | In-band JWT | Client WebSocket (RPC) |
| GET | `/api/v1/federation/ws` | HTTP Signature | Peer federation WebSocket |
| GET | `/api/v1/federation/trusted` | Bearer | List trusted federation peers |
| GET | `/api/v1/federation/status/{domain}` | Bearer | Peer quota status |
| PUT | `/api/v1/spaces/{space_id}/files/{id}` | Bearer | Upload encrypted file |
| GET | `/api/v1/spaces/{space_id}/files/{id}` | Bearer | Download encrypted file |
| HEAD | `/api/v1/spaces/{space_id}/files/{id}` | Bearer | File metadata |

File routes are only registered when file storage is configured.

## Configuration (Environment Variables)

**Required:**
- `DATABASE_URL` -- PostgreSQL connection string
- `TRUSTED_ISSUERS` -- Space-separated issuer URLs, or `issuer=jwks_url` pairs for explicit JWKS endpoints

**Optional:**
- `LISTEN_ADDR` (default `0.0.0.0:5379`)
- `AUDIENCES` -- Comma-separated JWT audience values
- `IDENTITY_HASH_KEY` -- Hex-encoded 32-byte HMAC key for rate limit privacy

**File storage:**
- `FILE_STORAGE_BACKEND` -- `none` (default), `local`/`fs`, or `s3`
- `FILE_STORAGE_PATH` -- Path for local backend (default `./data/files`)
- `FILE_S3_ENDPOINT`, `FILE_S3_ACCESS_KEY`, `FILE_S3_SECRET_KEY`, `FILE_S3_BUCKET` -- Required for S3
- `FILE_S3_REGION` (default `us-east-1`), `FILE_S3_USE_SSL` (default `true`)

**Federation:**
- `FEDERATION_TRUSTED_DOMAINS` -- Comma-separated peer domains
- `FEDERATION_TRUSTED_KEYS` -- Peer public keys
- `FEDERATION_FST_SECRET`, `FEDERATION_FST_PREVIOUS_SECRET` -- FST HMAC secrets
- `FEDERATION_MAX_CONNECTIONS`, `FEDERATION_MAX_SPACES`, `FEDERATION_MAX_RECORDS_PER_HOUR`, `FEDERATION_MAX_BYTES_PER_HOUR`, `FEDERATION_MAX_INVITATIONS_PER_HOUR` -- Quota limits

## Conventions

- **`#![forbid(unsafe_code)]`** on every crate.
- **Error types**: domain-specific enums with `thiserror`, `Clone + PartialEq + Eq` for testability. Map external errors early; never leak sqlx/reqwest types.
- **CBOR serialization**: `minicbor-serde`. Use `serde_bytes` for byte fields, `skip_serializing_if` for optional/zero-value fields.
- **Test isolation**: each DB test gets its own PostgreSQL schema (`test_{uuid}`), auto-created by `test_support::test_storage()`. Tests return `None` gracefully when `DATABASE_URL` is unset.
- **API tests**: use stub trait impls (`StubHealth`, `StubValidator`) + `tower::ServiceExt::oneshot` to test routes without a running server.
- **Async**: `#[tokio::test]` for async tests, `async_trait` for trait methods.
- Workspace edition: 2021, MSRV: 1.88.

## Immutable v1 Contracts

Frozen -- changes require a versioned migration:
- All `/api/v1/` route paths, `betterbase-rpc-v1` subprotocol, RPC frame types/error codes, WebSocket close codes 4000-4007
- Encryption envelope v4: `[0x04][IV:12][ciphertext+tag]`
- Space ID derivation: `UUID5(BETTERBASE_NS, "{issuer}\0{user_id}\0{client_id}")`
- `X-Protocol-Version: 1` response header

## Docker

- `Dockerfile` -- Multi-stage production build: Rust 1.88 -> debian:bookworm-slim, nonroot user, port 5379
- `Dockerfile.dev` -- Dev build with `cargo-watch` hot reload
