# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

`tempered` is a composable authentication **library** for Rust (pre-1.0). A
consumer picks one auth scheme (JWT, session, API key), enables capabilities
(2FA, elevation/"sudo", password reset, email verification, OAuth2, passkeys),
and the axum adapter auto-wires the matching routes.

Read `ARCHITECTURE.md` for the design. Plans and their status live in `docs/`:
`AUTH_SCHEMES_PLAN.md`, `REVIEW_CORRECTION_PLAN.md`, `FOLLOWUP_PLAN.md` (open work).

## Workspace layout

Dependency direction: `tempered_axum → tempered_adapters → tempered_core`.

- `src/tempered_core/` — domain types (`domain/`), port traits for stores and
  clients (`ports/`), strategy traits, transport-neutral `ErrorCategory`. No web
  or HTTP crates; keep it that way.
- `src/tempered_adapters/` — `CredentialScheme` (+ `JwtScheme` / `SessionScheme`
  aliases over a `TokenStrategy`), `ApiKeyScheme`, framework-agnostic `handlers/`,
  and backends in `persistence/`, `email/`, `oauth/`, `passkey/`. No axum crates.
- `src/tempered_axum/` — `auth_service()`, `wiring.rs` (capability slots →
  routes), middleware, axum route shims, API integration tests in `tests/api/`.
- `src/lib.rs` — the `tempered` facade; everything public is re-exported here.
  Examples import from the facade only.
- `examples/` — `quickstart.rs` (mirrored in the README), `composed_scheme.rs`,
  and standalone crates `jwt_standalone`, `oauth_axum`, `passkey_axum`, `api_key_axum`.

## Key patterns

- **Capability slots (typestate).** Each optional capability is a generic slot on
  `CredentialScheme` defaulting to `()`; `supports_*` fills it and the capability
  trait is implemented only for the filled slot. Adding a capability means a new
  slot threaded through every impl header.
- **Auto-wiring.** `wiring.rs` has a no-op impl for `()` and a route-mounting impl
  for the real slot. There are no per-route opt-ins on `auth_service`, only path
  overrides.
- **One scheme per service.** Multiple schemes are composed by the user on their
  own enum; do not add a library-level composite scheme.
- **Protected user routes** go through `.validated_router(...)` /
  `.validated_elevated_router(...)` and read `Extension<Claims>`.
- **Stores a strategy needs for correctness** (ban list, token epoch) are
  constructor parameters, not slots.

## Commands

```bash
cargo build --workspace
cargo test --workspace                 # API tests start Postgres/Redis via testcontainers: Docker must be running
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check -p tempered --no-default-features   # the lean build must keep compiling
cargo run -p tempered-example-jwt      # also: -example-oauth, -example-passkey, -example-api-key
cargo run --example quickstart         # needs JWT_SECRET
```

`just` wraps these (`just --list`).

sqlx queries build offline from `src/tempered_adapters/.sqlx/` (`SQLX_OFFLINE=true`).
After changing a query or migration, regenerate with `cargo sqlx prepare` against
a live database. Migrations live in `src/tempered_adapters/migrations/`;
`PostgresUserStore::new` does not run them.

## Conventions

- One well-described commit per plan task/subtask (conventional-commit prefixes).
- Cargo features `postgres`, `redis`, `oauth-client`, `postmark-email` gate the
  heavy backends; new heavy dependencies go behind a feature.
- In-memory `HashMap*` / `HashSet*` stores are dev/test only.
- Secrets come from the environment. `.env` is git-ignored; `.env.example` lists
  the keys. Never commit real values.
