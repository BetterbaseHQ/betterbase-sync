# less-sync-rs

Encrypted blob sync service for the Less platform, written in Rust. This is a port of [less-sync](https://github.com/lessismore-co/less-sync) (Go).

The server stores and syncs encrypted blobs on behalf of clients. It never sees plaintext — encryption and decryption happen client-side.

## Architecture

```
bins/
  server/             Entry point
  migrate/            Standalone migration runner
  federation-keygen/  Generate Ed25519 key pairs for federation

crates/
  core/       Protocol types, space IDs, validation
  auth/       JWT/JWKS validation, UCAN chains, DID keys, HTTP signatures, sessions
  storage/    PostgreSQL storage layer (spaces, changes, membership, files)
  realtime/   WebSocket broker for push notifications
  api/        Axum HTTP + WebSocket handlers, federation endpoints
  app/        Server configuration and startup
```

## Development

Requires Rust 1.88+ and PostgreSQL 17 for integration tests.

```bash
just check       # fmt + clippy + test
just test        # cargo test (no DB required — DB tests auto-skip)
just test-db     # spin up PostgreSQL in Docker, run full test suite, tear down
just bench-db    # same, but for benchmarks
just db-shell    # psql into the test database
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `TRUSTED_ISSUERS` | Yes | Space-separated issuer URLs (or `issuer=jwks_url`) |
| `AUDIENCES` | No | JWT audience validation |
| `LISTEN_ADDR` | No | Bind address (default `0.0.0.0:5379`) |
| `FILE_STORAGE_TYPE` | No | `local` (default) or `s3` |
| `FILE_STORAGE_PATH` | No | Path for local file storage |
| `IDENTITY_HASH_KEY` | No | HMAC key for rate-limit identity hashing |
| `SPACE_SESSION_SECRET` | No | HMAC key for session tokens |

## Docker

```bash
docker build -t less-sync-rs .              # production image
docker build -f Dockerfile.dev -t less-sync-rs:dev .  # dev image with hot reload
```

## License

MIT
