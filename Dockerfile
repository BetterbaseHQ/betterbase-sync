# syntax=docker/dockerfile:1.7

# --- Dependency cache ---
FROM rust:1.88-bookworm AS chef
RUN cargo install cargo-chef --locked --version 0.1.77
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# --- Rust build ---
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --locked --release --recipe-path recipe.json

COPY . .
RUN SQLX_OFFLINE=true cargo build --locked --release \
    -p betterbase-sync-server \
    -p betterbase-sync-migrate \
    -p betterbase-sync-federation-keygen

# --- Runtime ---
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 nonroot \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin nonroot \
    && mkdir -p /app /var/lib/betterbase-sync/files \
    && chown -R nonroot:nonroot /app /var/lib/betterbase-sync

WORKDIR /app

COPY --from=builder /app/target/release/betterbase-sync-server /app/server
COPY --from=builder /app/target/release/betterbase-sync-migrate /app/migrate
COPY --from=builder /app/target/release/betterbase-sync-federation-keygen /app/federation-keygen
COPY --chmod=755 docker/entrypoint.sh /usr/local/bin/betterbase-sync-entrypoint

USER nonroot
EXPOSE 5379

ENTRYPOINT ["/usr/local/bin/betterbase-sync-entrypoint"]
