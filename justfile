# List available recipes
default:
    @just --list

# Run all checks (format, lint, test)
check: fmt lint test-runner test

# Verify automatic database cleanup and exit status handling.
test-runner:
    python3 scripts/test-with-test-db.py
    python3 scripts/test-coverage-gate.py

# Format code
fmt:
    cargo fmt --all

# Run clippy linter
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Full suite with disposable PostgreSQL (or an explicitly supplied DATABASE_URL).
test *args:
    bash scripts/with-test-db.sh cargo test --workspace {{args}}

# Explicit fast mode; database-backed tests skip.
test-no-db *args:
    env -u DATABASE_URL -u BB_TEST_REQUIRE_DB cargo test --workspace {{args}}

# Run tests with verbose output
test-v *args:
    bash scripts/with-test-db.sh cargo test --workspace {{args}} -- --nocapture

# Rust coverage, including database tests, with automatic PostgreSQL cleanup.
coverage:
    bash scripts/with-test-db.sh bash scripts/coverage-rust.sh

# Run benchmarks
bench *args:
    cargo bench --workspace {{args}}

# Build all targets
build:
    cargo build --workspace

# Build release
build-release:
    cargo build --workspace --release

# Clean build artifacts
clean:
    cargo clean

# Docker settings for test database
_db_container := "betterbase-sync-test-db"
_db_port      := "15432"
_db_user      := "sync"
_db_pass      := "sync"
_db_name      := "sync_test"
_db_url       := "postgres://" + _db_user + ":" + _db_pass + "@localhost:" + _db_port + "/" + _db_name + "?sslmode=disable"

# Start a PostgreSQL container for tests
[private]
db-start:
    #!/usr/bin/env bash
    set -e
    if docker ps --format '{{{{.Names}}' | grep -q '^{{_db_container}}$'; then
        echo "Test database already running"
        exit 0
    fi
    if docker ps -a --format '{{{{.Names}}' | grep -q '^{{_db_container}}$'; then
        echo "Starting stopped test database..."
        docker start {{_db_container}}
    else
        echo "Creating test database..."
        docker run -d \
            --name {{_db_container}} \
            -p {{_db_port}}:5432 \
            -e POSTGRES_USER={{_db_user}} \
            -e POSTGRES_PASSWORD={{_db_pass}} \
            -e POSTGRES_DB={{_db_name}} \
            postgres:17-alpine
    fi
    echo "Waiting for PostgreSQL to accept connections..."
    until docker exec {{_db_container}} pg_isready -h 127.0.0.1 -U {{_db_user}} -d {{_db_name}} > /dev/null 2>&1; do
        sleep 0.2
    done
    echo "Test database ready on port {{_db_port}}"

# Stop and remove the test database container
db-down:
    docker rm -f {{_db_container}} 2>/dev/null || true

# Alias for the automated full suite; cleanup also runs on failure.
test-db *args:
    just test {{args}}

# Run storage benchmarks against a real PostgreSQL database
bench-db *args:
    #!/usr/bin/env bash
    set -e
    just db-start
    echo "Running benchmarks with DATABASE_URL..."
    DATABASE_URL="{{_db_url}}" cargo bench --workspace {{args}}
    just db-down

# PostgreSQL shell for the test database (must be running)
db-shell:
    docker exec -it {{_db_container}} psql -U {{_db_user}} -d {{_db_name}}
