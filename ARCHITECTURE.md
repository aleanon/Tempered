# Architecture

`tempered` is a composable authentication library. Its design goals, in order:

1. **Pick a scheme, get routes.** A consumer declares one auth scheme and the
   capabilities it wants; the matching HTTP routes are wired automatically.
2. **Swap any piece.** User stores, token strategies, email clients, and each
   capability's backing store are traits, so implementations are interchangeable.
3. **Framework-agnostic core.** The domain and scheme logic don't depend on a web
   framework; a thin per-framework adapter mounts them. An **axum** adapter ships
   today. (See [Known limitations](#known-limitations) for where this boundary is
   still leaky.)

## Workspace layout

The workspace has three library crates plus a facade:

```
tempered/                      facade crate: re-exports the common surface
  src/lib.rs

src/tempered_core/             pure domain + capability contracts
  src/domain/                  Email, Password, User, ApiKey, TwoFaCode,
                               SessionId, Passkey, tokens, errors, ...
  src/ports/                   store & client traits (UserStore, BannedTokenStore,
                               TwoFaCodeStore, EmailClient, OAuth*/Passkey stores)
  src/strategies/              Authenticator, AuthValidator
  src/http_authentication_scheme.rs   HttpAuthenticationScheme / HttpElevationScheme
  src/http_abstraction.rs      AuthRequest, ResponseBuilder
  src/error.rs                 ErrorCategory + ClassifyError (transport-neutral)

src/tempered_adapters/         concrete implementations
  src/authentication/          CredentialScheme (+ JwtScheme, SessionScheme aliases),
                               ApiKeyScheme, TokenStrategy
  src/auth_validation/         LocalJwtValidator and friends
  src/handlers/                framework-agnostic route logic (login, logout, ...)
  src/persistence/             HashMap*/HashSet* (dev) + Postgres/Redis stores
  src/email/                   MockEmailClient, PostmarkEmailClient
  src/oauth/                   OAuthFlow, Reqwest HTTP client
  src/passkey/                 PasskeyFlow, WebAuthn verification

src/tempered_axum/             the axum adapter
  src/auth_service.rs          auth_service() / AuthService builder
  src/wiring.rs                AutoWire: capability slots -> routes
  src/route_config.rs          route buckets, path overrides, elevated layer
  src/routes/                  axum handlers (signup, login, verify_2fa, oauth, ...)
  src/middleware.rs            validate_token / validate_elevated_token
  src/adapters.rs              axum AuthRequest / ResponseBuilder impls
  src/error.rs                 ErrorCategory -> http::StatusCode + IntoStatusMessage
```

Dependency direction is `tempered_axum → tempered_adapters → tempered_core`. The
`tempered` facade depends on all three.

## Layer responsibilities

### `tempered_core` — domain and contracts

Domain value objects (`Email`, `Password`, `User`, `TwoFaCode`, `ApiKey`,
`SessionId`, passkey and token types) and the **port traits** that back each
capability (`UserStore`, `BannedTokenStore`, `TwoFaCodeStore`, `EmailClient`, the
OAuth and passkey stores, …). It also defines the strategy traits `Authenticator`
and `AuthValidator`, which the schemes build on.

Core is where you look to understand *what* an auth operation means, independent
of transport. Implement its port traits to plug in a database or email provider.

### `tempered_adapters` — schemes, strategies, backends

The heart of the composition model lives here:

- **`CredentialScheme<U, T, F, L, R, M, O, K>`** — a typestate builder where each
  generic after the user store `U` and token strategy `T` is a **capability
  slot**: two-factor, elevation, password reset, email verification, OAuth,
  passkeys. A disabled slot is `()`; an enabled slot holds that capability's
  backend. `JwtScheme` and `SessionScheme` are aliases of `CredentialScheme` over
  a JWT or session `TokenStrategy`. `ApiKeyScheme` is a smaller scheme in the same
  style.
- **`TokenStrategy`** — the seam that makes "JWT vs. session" a one-trait choice:
  issuing, revoking, and validating a token are delegated to the strategy, so a
  new token type is a new `TokenStrategy` impl rather than a new scheme.
- **Handlers** (`handlers/`) — framework-agnostic functions that run a scheme
  operation and build a response through the `ResponseBuilder` trait.
- **Backends** (`persistence/`, `email/`, `oauth/`, `passkey/`) — concrete store
  and client implementations, in-memory for dev and Postgres/Redis/reqwest for
  production.

### `tempered_axum` — the axum adapter

Turns a scheme into a running service:

- **`auth_service(scheme, assets_dir)`** returns an `AuthService` builder.
- **Auto-wiring** (`wiring.rs`): `AutoWire::auto_wire` inspects the scheme's
  capability slots at compile time and mounts exactly the routes those
  capabilities imply, at the correct authorization level (public, login-validated,
  or elevation-validated). The scheme is the single source of truth — there are no
  per-route opt-ins, only path overrides.
- **Middleware** (`middleware.rs`): `validate_token` validates the session token
  and inserts the decoded `Claims` into the request extensions; a handler reads it
  via `Extension<Claims>`. `validate_elevated_token` does the same for the
  elevated ("sudo") layer.
- **Escape hatch**: `.validated_router(router)` and
  `.validated_elevated_router(router)` attach a consumer's own `axum::Router`
  behind the login or elevated middleware. Because identity arrives via
  `Extension<Claims>`, those handlers never name the scheme's generic type.

## Capability composition (typestate)

Each capability occupies a typed slot on `CredentialScheme`. Trait impls are
gated per slot, so a capability that isn't enabled does not exist at the call
site — calling `.supports_password_change()` is only possible once elevation is
enabled, and so on. This gives compile-time feature gating with no runtime
branching: routes you didn't ask for are never generated rather than being dead
code.

```rust
let scheme = JwtScheme::new(user_store, jwt_config, banned_token_store)
    .supports_registration()
    .supports_2fa(two_fa_store, email_client.clone())
    .supports_elevation(elevated_ban_store, elevated_config, |elevated| {
        elevated.supports_password_change().supports_account_deletion()
    })
    .supports_password_reset(reset_store, email_client)
    .build();
```

`auth_service(scheme, assets)` then reads those slots and mounts `/signup`,
`/verify-2fa`, `/elevate` + the elevated routes, and the password-reset routes,
alongside the always-present `/login`, `/logout`, and `/verify-token`.

## Request flow (login)

1. axum receives `POST /login` and the route handler in `tempered_axum/src/routes/`
   extracts the credentials.
2. It calls the framework-agnostic handler in `tempered_adapters/handlers/`, which
   runs `scheme.login(...)` and builds the response through a `ResponseBuilder`.
3. The scheme's `create_login_response` (an `HttpAuthenticationScheme` method,
   returning `Result<B::Response, ResponseBuilderError>`) sets the session cookie
   (`HttpOnly; Secure; SameSite=Lax`) and a JSON body.
4. `tempered_axum/src/adapters.rs` turns the built response into an axum
   `Response`.

On a subsequent request to a protected route, `validate_token` validates the
cookie and injects `Claims` before the handler runs.

## Design principles

- **Dependency inversion** — schemes depend on port traits, not concrete stores.
- **Capability segregation** — each capability is its own trait/slot, enabled
  independently.
- **Compile-time gating** — the type system decides which operations and routes
  exist; monomorphization keeps the abstraction cheap.
- **One source of truth** — the scheme's declared capabilities drive both the
  available operations and the wired routes.

## Known limitations

This section is deliberately honest about where the code does not yet match the
goals above; these are tracked for future work.

- **Only the axum adapter ships.** Actix/Rocket/Warp are possible given the
  handler/scheme split but are not implemented. The boundaries are now in place
  for it: `tempered_core` depends on **no** transport crate (errors classify into
  a neutral `ErrorCategory`; the axum layer maps that to `http::StatusCode`), and
  `tempered_adapters` pulls **no** axum crates (cookies go through the `cookie`
  crate). A second adapter would depend on `tempered_adapters` for the schemes and
  supply its own `ResponseBuilder` impl, routes, and `ErrorCategory -> status` map.
- **The HTTP-shaped traits still live in `tempered_core`.** `HttpAuthenticationScheme`,
  `ResponseBuilder`, and `AuthRequest` are transport-*neutral* (no `http` crate —
  they use `serde` for JSON bodies) but are HTTP-flavoured in spirit. They could be
  relocated to an HTTP-abstraction crate for a stricter "core = pure domain" split,
  but there is **no dependency benefit** (`serde` must stay in core for the domain
  types and the WebAuthn/OAuth `serde_json::Value` ports), so this is left undone.
