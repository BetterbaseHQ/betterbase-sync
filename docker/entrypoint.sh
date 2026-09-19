#!/bin/sh
set -eu

# Run database migrations
/app/migrate

# Ensure a federation signing key exists if FEDERATION_DOMAIN is set.
# --no-promote (plus keygen's auto-provision no-op when a primary exists)
# makes restarts safe: the primary key — and therefore the public key peers
# pinned via FEDERATION_TRUSTED_KEYS — never changes. Rotate deliberately by
# running federation-keygen with --kid or without --no-promote instead.
if [ -n "${FEDERATION_DOMAIN:-}" ]; then
  /app/federation-keygen --domain "$FEDERATION_DOMAIN" --no-promote
fi

exec /app/server
