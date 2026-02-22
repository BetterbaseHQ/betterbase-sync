#!/bin/sh
set -eu

# Build migration tool (and keygen if federation is configured) in one step
if [ -n "${FEDERATION_DOMAIN:-}" ]; then
  cargo build --locked -p betterbase-sync-migrate -p betterbase-sync-federation-keygen
else
  cargo build --locked -p betterbase-sync-migrate
fi

# Run migrations
"$CARGO_TARGET_DIR/debug/betterbase-sync-migrate"

# Generate federation signing key if FEDERATION_DOMAIN is set
if [ -n "${FEDERATION_DOMAIN:-}" ]; then
  "$CARGO_TARGET_DIR/debug/betterbase-sync-federation-keygen" --domain "$FEDERATION_DOMAIN"
fi

exec cargo watch -x "run --locked -p betterbase-sync-server"
