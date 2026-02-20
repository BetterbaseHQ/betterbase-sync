#!/bin/sh
set -eu

# Build migration tool (and keygen if federation is configured) in one step
if [ -n "${FEDERATION_DOMAIN:-}" ]; then
  cargo build --locked -p less-sync-migrate -p less-sync-federation-keygen
else
  cargo build --locked -p less-sync-migrate
fi

# Run migrations
"$CARGO_TARGET_DIR/debug/less-sync-migrate"

# Generate federation signing key if FEDERATION_DOMAIN is set
if [ -n "${FEDERATION_DOMAIN:-}" ]; then
  "$CARGO_TARGET_DIR/debug/less-sync-federation-keygen" --domain "$FEDERATION_DOMAIN"
fi

exec cargo watch -x "run --locked -p less-sync-server"
