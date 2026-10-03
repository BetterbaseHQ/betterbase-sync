# betterbase-sync

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Encrypted blob sync server for the [Betterbase](https://github.com/BetterbaseHQ/betterbase-dev) platform. The server only ever handles ciphertext -- clients encrypt before pushing and decrypt after pulling, so plaintext never leaves the device.

betterbase-sync provides WebSocket RPC (CBOR) and HTTP endpoints for syncing encrypted records and files, with real-time push notifications, cursor-based conflict resolution, and optional peer-to-peer federation.

## Quick Start

### As part of betterbase-dev (recommended)

```bash
# From the betterbase-dev root
just setup    # Clone repos, generate keys, create .env
just dev      # Start all services with hot reload

# Verify sync is running
curl http://localhost:5379/health
```

### Standalone

1. Set required environment variables:
   ```bash
   export DATABASE_URL="postgres://user:pass@localhost:5432/sync"
   export TRUSTED_ISSUERS="https://accounts.betterbase.dev"
   ```

2. Run database migrations:
   ```bash
   cargo run -p betterbase-sync-migrate
   ```

3. Run the server:
   ```bash
   cargo run -p betterbase-sync-server
   ```

4. Verify it's running:
   ```bash
   curl http://localhost:5379/health
   ```

The server listens on port 5379 by default.

### With file storage

```bash
# Local filesystem
export FILE_STORAGE_BACKEND=local
export FILE_STORAGE_PATH=./data/files

# S3-compatible
export FILE_STORAGE_BACKEND=s3
export FILE_S3_ENDPOINT=minio.internal:9000
export FILE_S3_ACCESS_KEY=access
export FILE_S3_SECRET_KEY=secret
export FILE_S3_BUCKET=betterbase-sync
```

### With federation

```bash
# Generate a federation key pair
cargo run -p betterbase-sync-federation-keygen

# Configure trusted peers
export FEDERATION_TRUSTED_DOMAINS="peer1.example.com,peer2.example.com"
export FEDERATION_FST_SECRET="<base64-secret>"
```

## Features

- **Zero-knowledge storage** -- the server stores and syncs only encrypted blobs; plaintext never touches the wire or disk.
- **WebSocket RPC** -- CBOR-encoded binary protocol (`betterbase-rpc-v1`) with real-time push notifications.
- **Encrypted file sync** -- upload and download encrypted files with wrapped DEKs. Pluggable backends: local filesystem or S3-compatible.
- **Epoch-based forward secrecy** -- rotating epochs with DEK rewrapping.
- **Federation** -- peer-to-peer sync across servers via HTTP Signatures, with quota tracking.
- **JWT + UCAN authorization** -- validates JWTs from trusted issuers via JWKS, with UCAN delegation and revocation.

## Architecture

The server is split into focused crates under `crates/` -- `core` (protocol types and validation), `auth` (JWT/JWKS, UCAN, HTTP signatures), `storage` (trait-based PostgreSQL layer), `realtime` (WebSocket broker), `api` (Axum HTTP/WS handlers), and `app` (config and startup). Binaries live in `bins/` (server, migrate, federation-keygen). All crates enforce `#![forbid(unsafe_code)]`.

```
core          <- no internal deps
auth          <- no internal deps
storage       -> core
realtime      -> core, auth, storage
api           -> core, auth, storage, realtime
app           -> all crates
```

## API Routes

All v1 routes are immutable contracts. Every response includes `X-Protocol-Version: 1`.

### Public Routes

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Health check (includes federation status if enabled) |
| GET | `/.well-known/jwks.json` | Federation JWKS endpoint |

### Client Routes (JWT Auth)

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/ws` | WebSocket RPC endpoint (auth via in-band notification) |

### File Routes (Bearer Auth)

| Method | Path | Description |
|---|---|---|
| PUT | `/api/v1/spaces/{space_id}/files/{id}` | Upload encrypted file |
| GET | `/api/v1/spaces/{space_id}/files/{id}` | Download encrypted file |
| HEAD | `/api/v1/spaces/{space_id}/files/{id}` | File metadata |

File routes are only registered when file storage is configured.

Uploads and garbage collection serialize per file using PostgreSQL advisory locks across server workers. Uploads queue cleanup before writing objects and clear that entry atomically when metadata commits, so failed uploads remain collectible. Once an upload owns its file lock, request cancellation lets its write and metadata bookkeeping finish before releasing the lock. Metadata commits recheck that the parent record is live in the same space. Collection rechecks the current queue entry's age and metadata while holding the file lock.

File locks use a separate, lazy PostgreSQL pool with the same maximum connection count as the metadata pool (10 by default). This lets a lock holder finish metadata queries even when other uploads are waiting for its lock. Budget database connections for both pools when file storage is enabled.

### Federation Routes

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/federation/ws` | HTTP Signature | Peer federation WebSocket |
| GET | `/api/v1/federation/trusted` | Bearer | List trusted peers |
| GET | `/api/v1/federation/status/{domain}` | Bearer | Peer quota status |

## Configuration

### Required Environment Variables

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `TRUSTED_ISSUERS` | Space-separated issuer URLs, or `issuer=jwks_url` pairs |

### Optional Environment Variables

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `0.0.0.0:5379` | HTTP listen address |
| `AUDIENCES` | -- | Comma-separated JWT audience values |
| `IDENTITY_HASH_KEY` | -- | Hex-encoded 32-byte HMAC key for rate limit privacy |

### File Storage

| Variable | Default | Description |
|---|---|---|
| `FILE_STORAGE_BACKEND` | `none` | `none`, `local`/`fs`, or `s3` |
| `FILE_STORAGE_PATH` | `./data/files` | Path for local backend |
| `FILE_S3_ENDPOINT` | -- | S3 endpoint (required for s3) |
| `FILE_S3_ACCESS_KEY` | -- | S3 access key (required for s3) |
| `FILE_S3_SECRET_KEY` | -- | S3 secret key (required for s3) |
| `FILE_S3_BUCKET` | -- | S3 bucket name (required for s3) |
| `FILE_S3_REGION` | `us-east-1` | S3 region |
| `FILE_S3_USE_SSL` | `true` | Use HTTPS for S3 |
| `FILE_DELETION_GRACE_SECS` | `86400` | Delay before removing tombstoned or abandoned file objects; must be greater than zero |

### Federation

| Variable | Default | Description |
|---|---|---|
| `FEDERATION_TRUSTED_DOMAINS` | -- | Comma-separated peer domains |
| `FEDERATION_TRUSTED_KEYS` | -- | Peer public keys |
| `FEDERATION_FST_SECRET` | -- | FST HMAC secret |
| `FEDERATION_FST_PREVIOUS_SECRET` | -- | Previous FST secret (for rotation) |
| `FEDERATION_MAX_CONNECTIONS` | -- | Max connections per peer |
| `FEDERATION_MAX_SPACES` | -- | Max spaces per peer |
| `FEDERATION_MAX_RECORDS_PER_HOUR` | -- | Record push rate limit |
| `FEDERATION_MAX_BYTES_PER_HOUR` | -- | Byte push rate limit |
| `FEDERATION_MAX_INVITATIONS_PER_HOUR` | -- | Invitation rate limit |

## Development

Federation integration tests run an edge server and a home server against separate PostgreSQL schemas. A disposable TCP proxy cuts their link to verify quota cleanup, cached-token restoration, and reconnection. Controlled peer fixtures cover stalled handshakes, RPC deadlines, cancellation, and concurrent calls. All listeners and database fixtures are managed by the tests.

For lifecycle changes, test sequences as well as individual calls: fail or cancel an operation, then retry, tombstone, collect, or reconnect. Place deterministic gates before dispatch, after backend dispatch but before completion, and between external I/O and database bookkeeping. Model backends whose work continues after their awaiting future is dropped. Assert the final invariant (bytes match live metadata, deletion grace starts at the tombstone, cached tokens survive transient failures, owned processes and containers are removed). Verify that new regressions fail against the previous implementation; coverage percentages alone cannot establish these properties.


### Prerequisites

- Rust 1.88+
- Python 3 for test-runner checks and coverage summaries
- Docker for automatic test PostgreSQL, or an existing PostgreSQL test database

### Commands

```bash
just check          # Format + lint + test (run before committing)
just test           # Full suite; automatically start and remove PostgreSQL
just test-db        # Alias for just test
just test-no-db     # Fast mode; skip database-backed tests
just coverage       # Rust coverage + >90% gates with automatic PostgreSQL
just bench-db       # Run storage benchmarks against real PostgreSQL
```

`just test`, `just check`, and `just coverage` run database-backed tests automatically. Each run creates a disposable PostgreSQL 17 container on a random loopback port and removes it on success, failure, or interruption. Each database test uses an isolated schema. Concurrent runs use separate containers. Coverage reports are written to `target/coverage/rust/`; coverage requires `cargo-llvm-cov` and the Rust `llvm-tools-preview` component.

Coverage fails unless LLVM line, region, and function coverage each exceed 90% overall and in every library crate and binary. Each crate must also exceed 90% production line coverage. Production counters exclude test sources; the HTML report retains tests for navigation. Stable Rust reports do not provide branch counters, so these gates do not claim branch coverage. CI runs the same coverage workflow against its PostgreSQL service.

Upload cancellation leaves the active write and metadata bookkeeping running under the file lock. File-collector cancellation stops the remaining batch while its active file operation finishes deletion and queue cleanup under the file lock. This keeps an already dispatched delete from racing a re-upload. The runner assigns a unique container name before launch and waits for an interrupted launch to finish before removing it. The test runner forwards `SIGINT`/`SIGTERM` to the command’s process group and waits for children to stop before removing PostgreSQL; an unresponsive group is killed after a five-second grace period.

If `DATABASE_URL` is supplied, these commands use that test database and leave it running. `BB_TEST_REQUIRE_DB=1` prevents database tests from silently skipping in the full suite and CI. Use `just test-no-db` for an explicit database-free run; direct `cargo test` still skips database tests when `DATABASE_URL` is absent. For manual debugging, `just db-start`, `just db-shell`, and `just db-down` manage the fixed-port database on port 15432.

### Docker

```bash
# Production build (multi-stage: Rust 1.88 -> debian:bookworm-slim)
docker build -t betterbase-sync .

# Dev build with hot reload
docker build -f Dockerfile.dev -t betterbase-sync-dev .
```

## Related

- [betterbase-dev](https://github.com/BetterbaseHQ/betterbase-dev) -- Platform orchestration
- [betterbase-accounts](../betterbase-accounts/) -- OPAQUE auth + OAuth 2.0 server
- [betterbase-inference](../betterbase-inference/) -- E2EE inference proxy
- [betterbase](../betterbase/) -- Client SDK (auth, crypto, discovery, sync, db)

## License

Apache-2.0
