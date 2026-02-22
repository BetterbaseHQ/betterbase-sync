# syntax=docker/dockerfile:1.7

FROM rust:1.88-bookworm AS builder
WORKDIR /app

COPY . .
RUN cargo build --locked --release \
    -p betterbase-sync-server \
    -p betterbase-sync-migrate \
    -p betterbase-sync-federation-keygen

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 nonroot \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin nonroot \
    && mkdir -p /app /var/lib/betterbase-sync/files \
    && chown -R nonroot:nonroot /app /var/lib/betterbase-sync

WORKDIR /app

COPY --from=builder /app/target/release/betterbase-sync-server /app/server
COPY --from=builder /app/target/release/betterbase-sync-migrate /app/migrate
COPY --from=builder /app/target/release/betterbase-sync-federation-keygen /app/federation-keygen
COPY docker/entrypoint.sh /usr/local/bin/betterbase-sync-entrypoint
RUN chmod +x /usr/local/bin/betterbase-sync-entrypoint

USER nonroot
EXPOSE 5379

ENTRYPOINT ["/usr/local/bin/betterbase-sync-entrypoint"]
