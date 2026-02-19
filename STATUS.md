# less-sync-rs Inventory

Last updated: 2026-02-19

## Repository State
- Branch: `main`
- HEAD: `51ee6e8` (`Add rotation-safe federation signing key lifecycle`)
- Working tree status at update time: in progress (websocket federation restore integration slice)

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
1. `less-sync-api`: `140`
2. `less-sync-app`: `21`
3. `less-sync-auth`: `78`
4. `less-sync-core`: `29`
5. `less-sync-realtime`: `17`
6. `less-sync-storage`: `45`
7. `less-sync-federation-keygen`: `4`
8. Total passing tests: `334`

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
- Persists with promotion-by-default to the active signing key, with `--no-promote` support for staged rollover workflows.
- Emits operator-friendly output including `FEDERATION_TRUSTED_KEYS` entry.
9. Federation signing key lifecycle:
- Added migration `012_federation_key_lifecycle.sql` with explicit `is_active`/`is_primary` state and deterministic backfill of existing primary key.
- Storage now supports promoting and deactivating federation signing keys and loading the active primary keypair directly.
- Active-key JWKS publication now naturally supports overlap windows (old keys remain published until deactivated).
- App startup now selects outbound federation signing material from explicit active-primary storage state instead of insertion order.
10. HTTP/API:
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
11. File storage backends:
- Disabled mode.
- Local filesystem mode.
- Minimal S3-compatible mode via `object_store` (`AmazonS3Builder`).
- S3 coverage is currently config/builder-level (no full MinIO integration suite yet).
12. Federation outbound peer manager:
- Dedicated `federation_client` module in `less-sync-api` with focused module boundaries (`mod`, `peer`, `wire`, tests).
- Signed federation websocket dialing using `less_sync_auth::sign_http_request`.
- Per-peer connection reuse and per-space FST token tracking.
- Forwarding primitives now implemented for `subscribe`, `push`, and `fed.invitation`.
- Pull orchestration now collects streamed `RPC_CHUNK` frames into typed pull chunks.
- Retry behavior now reconnects once on closed/connect transport failures while preserving request identity.
- Subscription restore flow now replays cached per-space FST tokens back through `subscribe`.
- Local tests now cover request forwarding, pull chunk collection, reconnect retry behavior, and FST token persistence/restore behavior.
13. Runtime federation forwarding integration:
- Client websocket `push` now forwards to remote home servers when `space.home_server` is set and a federation forwarder is configured.
- `invitation.create` now supports remote delivery via `params.server` for trusted peers, including explicit bad-request and internal-error mappings.
- API state now carries a pluggable federation forwarder, and app startup wires one from stored federation signing keys when available.
- New websocket tests cover forwarded push, trusted/untrusted invitation forwarding, and forwarding failure behavior.
14. Websocket remote-home federation orchestration:
- Client websocket `subscribe` now federates remote-home subscriptions through the forwarder to establish remote peer-manager token state.
- Client websocket remote-home `push` now attempts `restore_subscriptions` and retries once after transient forwarding failure.
- Websocket tests now cover remote-home subscribe forwarding and restore-plus-retry push behavior.

## Gaps and Open Work
1. Runtime coverage for remote-home `pull` federation orchestration and chunk forwarding remains limited.
2. Benchmark parity with Go has not been ported.
3. S3 integration tests are intentionally minimal; optional MinIO smoke tests can be added later.

## Next Recommended Slice
1. Add app-level integration coverage for storage-backed federation key publication and runtime federation config behavior.
2. Expand federation integration coverage for peer status/trusted metadata endpoints.
3. Add runtime coverage for remote-home `pull` federation orchestration and chunk forwarding.
