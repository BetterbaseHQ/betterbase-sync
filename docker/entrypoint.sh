#!/bin/sh
set -eu

# Run database migrations
/app/migrate

# Generate federation signing key if FEDERATION_DOMAIN is set
if [ -n "${FEDERATION_DOMAIN:-}" ]; then
  /app/federation-keygen --domain "$FEDERATION_DOMAIN"
fi

exec /app/server
