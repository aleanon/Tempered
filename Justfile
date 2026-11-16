default:
    @just --list

# Build every crate and example
build:
    cargo build --workspace

# Run all tests (the API tests need Docker for testcontainers)
test *args:
    cargo test --workspace {{ args }}

# Clippy with warnings as errors
lint:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

fmt:
    cargo fmt --all

# The facade must keep compiling without the heavy backends
check-lean:
    cargo check -p tempered --no-default-features

# Run an example crate: jwt, oauth, passkey, api-key
example name:
    cargo run -p tempered-example-{{ name }}

# Start local Postgres + Redis for manual work against the real stores
db-up:
    docker run --name tempered-pg -e POSTGRES_PASSWORD=password -p 5432:5432 -d postgres:15.4-alpine
    docker run --name tempered-redis -p 6379:6379 -d redis:7.0-alpine

db-down:
    -docker rm -f tempered-pg tempered-redis

# Apply the shipped migrations to DATABASE_URL
migrate:
    cd src/tempered_adapters && cargo sqlx migrate run

# Refresh the offline sqlx query data after changing a query or migration
sqlx-prepare:
    cd src/tempered_adapters && cargo sqlx prepare

generate-secret length="64":
    openssl rand -base64 {{ length }}
