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
- **Epoch-based forward secrecy** -- key generation epochs with DEK rewrapping.
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

### Prerequisites

- Rust 1.88+
- PostgreSQL 17 (or Docker for `just test-db`)

### Commands

```bash
just check          # Format + lint + test (run before committing)
just test           # Run tests (DB tests skip without DATABASE_URL)
just test-db        # Spin up Postgres, run all tests including DB, tear down
just bench-db       # Run storage benchmarks against real PostgreSQL
```

Unit tests run without a database via `just test`. For the full suite including storage tests, use `just test-db` -- this starts a PostgreSQL container on port 15432, runs all tests, then removes the container.

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
