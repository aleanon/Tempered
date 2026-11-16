# tempered

A quick way to add authentication to a Rust backend. You pick an auth **scheme**
(JWT, session, API key), turn on the **capabilities** you want (2FA, elevation
/"sudo", OAuth2/OIDC, passkeys, password reset, email verification), and the
matching HTTP routes are **auto-wired** for you. Everything is built from
composable pieces — user stores, token strategies, email clients, and capability
backends are all swappable behind traits.

The core is framework-agnostic; an [axum](https://github.com/tokio-rs/axum)
adapter ships today.

> Status: early / pre-1.0. APIs may change. See [`ARCHITECTURE.md`](ARCHITECTURE.md)
> for the design and [`docs/AUTH_SCHEMES_PLAN.md`](docs/AUTH_SCHEMES_PLAN.md) for
> the roadmap.

## Quickstart (JWT)

```rust
use axum::{Extension, Router, routing::get};
use tempered::{
    Claims, ExposeSecret, HashMapTokenEpochStore, HashMapUserStore, HashSetBannedTokenStore,
    JwtAuthConfig, JwtScheme, Secret, auth_service,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let jwt_config = JwtAuthConfig {
        jwt_cookie_name: "jwt".to_string(),
        // Load this from the environment in real code; keep it >= 32 random bytes.
        jwt_secret: Secret::new(std::env::var("JWT_SECRET")?),
        token_ttl_in_seconds: 3600,
        // When set, tokens carry these claims and validation requires them, so a
        // token signed with the same secret for another service is rejected.
        audience: Some("my-app".to_string()),
        issuer: Some("my-app".to_string()),
    };

    // Declare the scheme and the capabilities you want. Each `supports_*` call
    // auto-wires its route(s) in `auth_service` below — there are no route
    // opt-ins to remember.
    let scheme = JwtScheme::new(
        HashMapUserStore::new(),        // swap for PostgresUserStore in production
        jwt_config,
        HashSetBannedTokenStore::new(), // swap for RedisBannedTokenStore in production
        HashMapTokenEpochStore::new(),  // swap for RedisTokenEpochStore in production
    )
    .supports_registration()
    .build();

    // `auth_service` reads the declared capabilities and mounts the routes
    // (`/login`, `/logout`, `/signup`, `/verify-token`, ...) at the right authz
    // level. `assets_dir` serves an optional SPA; pass an empty dir for API-only.
    let service = auth_service(scheme, "assets".to_string())
        // Attach your own protected routes — see below.
        .validated_router(Router::new().route("/whoami", get(whoami)));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    service.run(listener).await?;
    Ok(())
}

// A login-protected handler. The login middleware validates the `jwt` cookie and
// injects `Claims` into the request extensions, so your handler just extracts it
// — you never name the scheme's generic type.
async fn whoami(Extension(claims): Extension<Claims>) -> String {
    format!("logged in as {}", claims.sub.expose_secret())
}
```

This is [`examples/quickstart.rs`](examples/quickstart.rs), which is compiled with
the workspace: `JWT_SECRET=... cargo run --example quickstart`.

## Adding your own protected routes

You don't wire auth into individual handlers. Build a normal `axum::Router` and
hand it to the service:

- `.validated_router(router)` — protected by the regular login session.
- `.validated_elevated_router(router)` — protected by a short-lived elevated
  ("sudo") token; requires the `.supports_elevation(...)` capability.

Handlers in those routers read the authenticated identity via
`Extension<Claims>`. The middleware inserts it after validating the token, so the
scheme's generics stay fully inferred and never leak into your route code.

## Capabilities

Turn these on with `.supports_*` on the scheme builder; the routes appear
automatically:

| Capability | Builder | Adds |
|---|---|---|
| Registration | `.supports_registration()` | `POST /signup` |
| Two-factor | `.supports_2fa(store, email_client)` | `POST /verify-2fa` |
| Elevation ("sudo") | `.supports_elevation(ban_store, config, \|e\| ...)` | `POST /elevate`, elevated routes |
| Password reset | `.supports_password_reset(store, email_client)` | initiate + complete routes |
| Email verification | `.supports_email_verification(...)` | `POST /verify-email` |
| OAuth2 / OIDC | `.supports_oauth(flow)` | provider start + callback routes |
| Passkeys (WebAuthn) | `.supports_passkeys(flow)` | passkey ceremony routes |

Login, logout, and verify-token are always present. Every default path can be
overridden on the service builder (e.g. `.login("/signin")`).

## Swapping implementations

Every moving part is a trait, so you choose the backend:

- **User store:** `HashMapUserStore` (dev) or `PostgresUserStore` (Argon2id).
- **Banned-token store:** `HashSetBannedTokenStore` (dev) or `RedisBannedTokenStore`.
- **Token-epoch store** (revoke-all on password change / account deletion):
  `HashMapTokenEpochStore` (dev) or `RedisTokenEpochStore`.
- **Capability stores:** 2FA codes and password-reset tokens have in-memory
  `HashMap*` (dev) and Redis (prod) implementations. Sessions, API keys,
  email-verification tokens, OAuth state/identity, and passkey
  challenges/credentials currently ship in-memory only — implement the port
  trait for production (see [`docs/FOLLOWUP_PLAN.md`](docs/FOLLOWUP_PLAN.md)).
- **Email client:** `MockEmailClient`, `PostmarkEmailClient`, or your own `EmailClient`.
- **Token strategy:** JWT and session are both `CredentialScheme`s over a
  `TokenStrategy`; implement the trait to add a new token type.

> The in-memory `HashMap*`/`HashSet*` stores are for development and tests only.
> Several keep secrets unhashed and without expiry — use the Postgres/Redis
> stores in production.

## Examples

Runnable, self-contained (offline) examples live in [`examples/`](examples/):

```bash
cargo run -p tempered-example-jwt       # full JWT service + bundled frontend
cargo run -p tempered-example-oauth     # OAuth2/OIDC with an embedded mock provider
cargo run -p tempered-example-passkey   # WebAuthn/passkeys with a simulated authenticator
cargo run -p tempered-example-api-key   # API-key scheme
```

Each opens on <http://localhost:3000>.

## Workspace layout

- `tempered_core` — domain types, capability traits, and ports (store/email traits).
- `tempered_adapters` — schemes (`JwtScheme`, `SessionScheme`, `ApiKeyScheme`),
  token strategies, and concrete store/email/OAuth/passkey backends.
- `tempered_axum` — the axum adapter: `auth_service`, route handlers, middleware,
  and the auto-wiring layer.
- `tempered` — a facade crate that re-exports the common surface.
