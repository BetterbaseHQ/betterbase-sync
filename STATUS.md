# less-sync-rs Inventory

Last updated: 2026-02-19

## Repository State
- Branch: `main`
- HEAD: `5639509` (`Refactor federation RPC handlers into focused modules`)
- Working tree status at update time: in progress (federation quota + HTTP metadata/status slice)

## Workspace Inventory
1. Crates:
- `core`
- `auth`
- `storage`
- `realtime`
- `api`
- `app`
2. Binaries:
- `bins/server`
- `bins/migrate`
- `bins/federation-keygen`

## Test Inventory
Rust local tests (`cargo test --workspace --all-features`):
1. `less-sync-api`: `126`
2. `less-sync-app`: `21`
3. `less-sync-auth`: `78`
4. `less-sync-core`: `27`
5. `less-sync-realtime`: `17`
6. `less-sync-storage`: `44`
7. `less-sync-federation-keygen`: `3`
8. Total passing tests: `316`

Go baseline (reference from original local suite):
1. `467` tests
2. `20` benchmarks

## Implemented Capability Inventory
1. Core protocol and deterministic primitives:
- Protocol types for RPC/WS and record validation.
- Space ID deterministic derivation and vectors.
2. Auth/crypto:
- JWT/JWKS validation.
- UCAN chain validation (permission/resource/depth/etc).
- did:key support.
- Session and federation token primitives.
3. Storage:
- Postgres-backed storage trait implementation with migrations.
- Records, membership, invitations, DEKs/file DEKs, epoch/rewrap flows.
- Revocation persistence APIs.
4. Realtime and WS RPC:
- Auth-first handshake, typed frame handling, connection lifecycle.
- Subscribe/push/pull.
- `token.refresh`, `space.create`.
- `membership.append|list|revoke`.
- `invitation.create|list|get|delete`.
- `epoch.begin|complete`.
- `deks.get|rewrap`.
- `file.deks.get|rewrap` and legacy aliases.
- Presence/event notifications and broker fanout behavior.
5. Federation WS/runtime path:
- Dedicated `/api/v1/federation/ws` upgrade boundary with HTTP-signature trust validation.
- Federation-only RPC surface split from client RPC methods.
- Federation `subscribe` supports UCAN or FST validation and returns refreshed FST tokens.
- Federation `push`/`pull` enforce UCAN authorization independent of client JWT DID context.
- Federation quotas include connection caps, active subscription caps with unsubscribe/disconnect cleanup, and per-peer push record/byte rolling-hour limits.
- Federation route tests cover unsupported-method rejection and UCAN/FST subscribe-push-pull behavior.
6. Federation HTTP metadata/status surfaces:
- `GET /.well-known/jwks.json` (public metadata route)
- `GET /api/v1/federation/trusted` (authenticated trusted-domain view)
- `GET /api/v1/federation/status/{domain}` (authenticated quota/status view)
- JWKS route now emits cache headers and status route rejects unknown peers when trusted-domain allowlist is configured.
7. App/runtime federation wiring:
- Parses federation runtime env config for trusted domains/keys, FST secrets, and quota overrides.
- Wires federation authenticator and FST token keys into `ApiState` when configured.
- Loads federation public signing keys from storage and publishes them through JWKS route metadata.
8. Federation keygen bootstrap command:
- `bins/federation-keygen` now generates Ed25519 federation signing keys.
- Supports deterministic federation key-id construction via `--domain` and optional `--kid`.
- Optionally persists generated key material into Postgres (`--database-url` / `DATABASE_URL`) through storage APIs.
- Emits operator-friendly output including `FEDERATION_TRUSTED_KEYS` entry.
9. HTTP/API:
- Bearer auth middleware and `/health`.
- `/api/v1/ws`.
- File endpoints `/api/v1/spaces/{space_id}/files/{id}` with:
- scope enforcement
- personal/shared-space authz
- UCAN checks for shared spaces
- UCAN revocation checks for shared-space chains (HTTP and WS authz)
- strict header/body validation
- idempotent PUT semantics
- object blob backend via `object_store`.
10. File storage backends:
- Disabled mode.
- Local filesystem mode.
- Minimal S3-compatible mode via `object_store` (`AmazonS3Builder`).
- S3 coverage is currently config/builder-level (no full MinIO integration suite yet).

## Gaps and Open Work
1. Federation peer manager and forwarding/integration paths are not yet ported.
2. Federation key lifecycle still needs rotation/operational workflow hardening beyond initial key generation.
3. Benchmark parity with Go has not been ported.
4. S3 integration tests are intentionally minimal; optional MinIO smoke tests can be added later.

## Next Recommended Slice
1. Port federation peer-manager forwarding flows and additional federation local tests.
2. Add federation key rotation and operator workflow coverage on top of the new keygen bootstrap command.
3. Expand federation integration coverage for peer status/trusted metadata endpoints.
