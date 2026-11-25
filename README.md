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
        // Load this from the environment in real code. Shorter than 32 bytes
        // panics at startup (`openssl rand -base64 48` makes a good one).
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
    // level. `assets_dir` serves an optional SPA (never its dotfiles); pass an
    // empty dir for API-only.
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
- `.verified_router(router)` — a login session **and** a verified email
  address (403 otherwise); requires `.supports_email_verification(...)`. The
  address is looked up on every request, so verifying takes effect at once.
- `.validated_elevated_router(router)` — protected by a short-lived elevated
  ("sudo") token; requires the `.supports_elevation(...)` capability.

The tiers nest: public routes (login, signup), then any logged-in user
(logout, `/verify-token`, `/verify-email`, `/verify-email/resend`, account
deletion), then verified users, then elevated. Verifying needs both the token
from the email and a login to the account it was sent for: the token alone
would let the inbox owner prove an account someone else created with their
address. A page that opens the link without a session should send the user to
log in first, then post the token. With email verification on, the
library's own credential-changing routes sit in the verified tier: password
change, passkey enrolment and `/elevate` (so everything elevated is reached by
a verified user). Without email verification the scheme cannot tell, and those
routes are plain login routes.

`/elevate` asks for the password again and, for an account with 2FA, the
second factor too: it answers `206 {"loginAttemptId": ..}` like a 2FA login,
and `POST /elevate/verify-2fa` with `{"loginAttemptId", "2FACode"}` (for the
logged-in user; there is no email in the body) sets the elevated cookie.

Password change and account deletion ask for no current password: the
elevated tier is that check. Put them behind it
(`.supports_elevation(.., |e| e.supports_password_change().supports_account_deletion())`)
unless a stolen session cookie being enough to set a new password is
acceptable for your app.

Handlers in those routers read the authenticated identity via
`Extension<Claims>`. The middleware inserts it after validating the token, so the
scheme's generics stay fully inferred and never leak into your route code. `claims.uid` is the account's stable id (`UserId`), and
`claims.sub` is its address now. Key your own tables on `uid`, which stays the same
when the user changes their address (`IdentityClaims::user_id()` gives it for any
scheme, sessions included).

## Capabilities

Turn these on with `.supports_*` on the scheme builder; the routes appear
automatically:

| Capability | Builder | Adds |
|---|---|---|
| Registration | `.supports_registration()` | `POST /signup` (a taken address gets the same `201`; with email verification its owner is mailed a notice) |
| Two-factor | `.supports_2fa(store, email_client)` | `POST /verify-2fa` |
| Elevation ("sudo") | `.supports_elevation(ban_store, config, \|e\| ...)` | `POST /elevate`, `POST /elevate/verify-2fa`, elevated routes |
| Authenticator apps (TOTP) | `.supports_totp(store, "Your App")`, after 2FA and elevation | `POST /elevated/totp/{start,confirm,disable,recovery-codes}`. An account with an app gets no mailed code: `/verify-2fa` takes the app's code or a recovery code in `2FACode` |
| Password reset | `.supports_password_reset(store, email_client)` | initiate + complete routes. Initiation answers at once and sends the mail afterwards, so its timing does not reveal whether the address has an account |
| Email verification | `.supports_email_verification(...)` | `POST /verify-email`, `POST /verify-email/resend` (both logged in); signup sends the link; credential changes need a verified address |
| OAuth2 / OIDC (with PKCE) | `.supports_oauth(flow)` | provider start + callback routes. A callback that fails (including a provider `error=`, e.g. the user cancelled, which answers `401`) clears the state cookie |
| Passkeys (WebAuthn) | `.supports_passkeys(flow)` | passkey login routes (public) + enrolment routes (logged-in user only; add `e.supports_passkey_enrollment()` in the elevation closure to require a fresh re-authentication). A passkey login skips 2FA unless you add `.passkey_login_requires_2fa()`: then a 2FA account gets `206 { loginAttemptId, email }` and finishes at `/verify-2fa` |

Providers come from `tempered::oauth_providers`: `google(..)`,
`microsoft(tenant, ..)` and `github(..)` presets, or `discover(http, name,
issuer, ..)` for any OpenID Connect provider (it reads
`{issuer}/.well-known/openid-configuration` and refuses a document for
another issuer). Register each with `OAuthFlow::with_provider`. For an OIDC
provider (`oidc: Some(..)`) the login sends a nonce and is decided by the
ID token: its signature is checked with the provider's published keys
(cached for an hour), and so are its issuer, audience (`azp` when there are
several), expiry and nonce. Only asymmetric algorithms are accepted. GitHub
is plain OAuth2: the address is the primary one from its emails endpoint.
Microsoft needs a tenant id (multi-tenant `common` issuers cannot be pinned)
and does not mark addresses verified, so a first Microsoft login cannot take
over an existing account by address. Apple is not supported yet: it sends
the address only with a cross-site `form_post` callback.

An OAuth login follows the same rules as a password login: the first login for
an email creates the account, later ones log in to it, and an account that
requires 2FA is still asked for its code: instead of issuing a session, the
callback redirects to `.oauth_two_fa_redirect(path)` with `?oauth_2fa=required`
and hands the `loginAttemptId` and `email` to the page in a short-lived
`__Host-oauth_2fa` cookie, for the usual `verify-2fa` call.

The first time a provider login reaches an account that was created by signup,
the account is trusted as it is only if its address has been proven: by the
email-verification capability, or by another provider already linked to it.
Otherwise whoever signed up may not own the address, so before the user is let
in the account's password is replaced with a random one, its sessions are
revoked and its passkeys are removed. If the scheme offers email verification
and the address was never confirmed, the account's 2FA requirement is switched
off as well; without email verification the scheme cannot tell, and 2FA stays.
Enable `.supports_email_verification(...)` alongside OAuth: without it every
signup account counts as unproven, and a genuine user loses their password on
their first provider login. A provider login marks the address verified: the
provider vouches for it (the flow refuses an address the provider has not
verified).

Once linked, a provider identity is its `subject`, not its email. If the user
changes their address at the provider, the identity still logs in to the
account it was linked to. The link is not moved to the new address, and that
login no longer marks the account's (old) address verified. Changing the
account's own address is a separate feature (plan 8.9).

Login, logout, and verify-token are always present. Every default path can be
overridden on the service builder (e.g. `.login("/signin")`).

### Cookie names

Name your auth cookies with the `__Host-` prefix (`__Host-jwt`,
`__Host-elevated_jwt`, `__Host-session`). The browser then takes the cookie
only from this exact host, so a sibling subdomain (a forgotten staging site,
user content on `*.example.com`) cannot overwrite it with a session it
controls. The cookies this library sets already meet the prefix's rules
(`Secure`, `Path=/`, no `Domain`). The OAuth state cookie uses the prefix by
default (`__Host-oauth_state`).

### Cross-site requests

The library's state-changing routes (everything but GET and HEAD) answer
`403` to a request a browser marks as cross-site: `Sec-Fetch-Site:
cross-site`, or, from browsers that don't send that header, an `Origin` that
is not the `Host`. Same-site requests (`app.example.com` calling
`api.example.com`) pass, and so do clients that send neither header (curl,
mobile apps). It backs up `SameSite=Lax` cookies and JSON-only bodies. Its
main job is the routes that need no cookie: it keeps another site from
logging a visitor in to an account it picked. Layer
`tempered_axum::middleware::refuse_cross_site` over your own routers for the
same rule.

### Session lifetime

`SessionScheme` sessions end two ways. They expire after `ttl_in_seconds`
unused, and each request restarts that clock. They also end at
`max_lifetime_in_seconds` after login, however busy they are, which limits how
long a stolen cookie stays good. `SessionConfig::new(cookie, ttl)` sets the
absolute lifetime to 24 hours (`DEFAULT_MAX_SESSION_LIFETIME_SECONDS`);
change it with `.max_lifetime(seconds)`. A JWT has no sliding expiry: its
`token_ttl_in_seconds` is already its absolute lifetime.

### Passwordless login by email

`.supports_email_login(EmailLogin::code(store))`, on a scheme with 2FA,
lets a user log in with a mailed six-digit code. `store` is a code store of
its own (with Redis: `RedisTwoFaCodeStore::new(conn).with_namespace(
"email_login")`), so a sign-in code is never a second factor and never
disturbs a pending 2FA login: `POST /email-login/start
{ email }` answers `{ loginAttemptId }` at once, for any address, and mails
the code afterwards only if the account exists (so neither the answer nor
its timing reveals that); `POST /email-login/verify { email,
loginAttemptId, code }` logs in. `EmailLogin::link(page)` also mails a link
to `page` (`EmailLogin::link(store, page)`) with `email`, `loginAttemptId`
and `code` in the query; the page
posts them (a link that logged in on `GET` would be used up by mail
scanners that open links). The code is single-use with an attempt
budget. An account that requires 2FA needs a second factor other than the
inbox: with an authenticator app it is asked for the app's code (`206`);
without one it is refused (`403`) and signs in with its password.

### Changing the email address

`.supports_email_change(store)`, after `.supports_email_verification(..)`,
lets a user move their account to another address. `POST
/elevated/email/change { newEmail }` (elevated when the scheme has
elevation; `/email/change` for a verified address otherwise) answers
`202` at once, whether or not the address is taken. Afterwards a token
goes to the new address (`Mail::ConfirmEmailChange`) and a notice to the
old one (`Mail::EmailChangeRequested`). A taken address gets
`Mail::AlreadyRegistered` instead. `POST /email/change/confirm { token }`,
logged in as the same account, moves it. Its passkeys, provider links,
authenticator app and API keys go with it, the new address counts as
verified, and every session ends. `store` is `RedisEmailChangeStore` (or
`HashMapEmailChangeStore` in tests); a token lives an hour, and a newer
request replaces an older one. Your own tables keyed by the address need
moving too: listen for the change in your app, or key them on something
else.

### Account self-service

With OAuth on, a logged-in user can manage their provider logins:
`GET /oauth/links` lists the providers linked to the account; `POST
/oauth/{provider}/link` (a verified address needed, like any new way in;
`/elevated/...` with `e.supports_oauth_linking()`) sends them to the
provider and attaches that provider identity to *their* account, whatever
address the provider reports. A provider that does not vouch for the
account's own address can be linked only once that address is proven
(verified, or vouched for by an earlier link) (the callback is the
provider's usual one; a separate state cookie tells a link from a login,
and logs nobody in); `DELETE /oauth/links/{provider}` unlinks it.

With passkeys on: `GET /passkey/credentials` lists `{ id, name }`, and
`PATCH /passkey/credentials/{id} { name }` and `DELETE
/passkey/credentials/{id}` rename or remove one, at the enrolment tier
(under `/elevated` with `e.supports_passkey_enrollment()`). Another user's
id is a `404`.

### API keys for your users

`.supports_api_key_management(store, ["read", "write"])` on the login
scheme lets users manage their own keys, in the store an `ApiKeyScheme`
validates against. The second argument is the scopes a user may give their
own key; any other is refused (`400`), so nobody grants themselves
`admin`:
`GET /api-keys` lists `{ id, prefix, scopes, createdAt, expiresAt,
lastUsedAt }` and the `allowedScopes`; `POST /elevated/api-keys { scopes, expiresInDays }` issues
one and answers the key once (`201 { id, apiKey, expiresAt }`); `DELETE
/elevated/api-keys/{id}` revokes it. Without elevation the two changes
need a verified address instead (no `/elevated`). An expired key is
refused, use is recorded at most once a minute, and deleting the account
deletes its keys. On the service side, guard a router with
`from_fn(|req, next| require_scope("invoices:read", req, next))` inside
the key check (`401` without a key, `403` without the scope).

### Devices (session schemes)

A session scheme serves `GET /sessions` and `DELETE /sessions/{handle}` to
any logged-in user. The list holds their sessions, newest use first:
`{ handle, createdAt, lastSeen, userAgent, current }`, where `userAgent` is
the browser of the session's first authenticated request and `current`
marks the one asking. `handle` names a session without being it (a hash of
the id, which is a credential). Ending a session logs that device out.

### Refresh tokens and bearer clients

`JwtScheme::supports_refresh_tokens(RefreshTokens::new(store, ttl))` issues
a refresh token with every login, in an `HttpOnly`, `SameSite=Strict`
cookie (`__Host-refresh`), and serves `POST /refresh`, which trades it for
a new JWT and a new refresh token. Keep `token_ttl_in_seconds` short (a few
minutes) and let the refresh token carry the session:

- Each refresh token works once. Presenting a used one means a copy is out
  there, so every token of that login is revoked (the owner logs in again).
- Logout, password change and account deletion revoke them; a login's
  refresh tokens all expire `ttl` after it (rotation does not extend it).
- Use `RedisRefreshTokenStore` in production.

Every JWT route also accepts `Authorization: Bearer <jwt>`. For clients
that cannot use cookies (mobile apps, a front end on another origin),
`.tokens_in_body()` adds `accessToken`, `refreshToken`, `tokenType` and
`expiresIn` to login responses, and `/refresh` takes
`{ "refreshToken": ... }`. Leave it off for browser apps on your own
origin: a token a script can read is one an XSS can steal.

### Authenticator apps and recovery codes

With `.supports_totp(store, issuer)` a user can add an authenticator app
(RFC 6238: SHA-1, six digits, 30 seconds) as their second factor. All four
routes are elevated, so a stolen session alone cannot add or remove one:

1. `POST /elevated/totp/start` answers `{ secret, otpauthUri }`. Show the URI
   as a QR code (and the base32 secret for typing in). Nothing changes yet.
2. `POST /elevated/totp/confirm { code }` with a code from the app turns it
   on (and 2FA with it) and answers `{ recoveryCodes }`: ten single-use
   codes like `abcde-23456`, stored only as hashes. Show them once.
3. From then on, the login's `/verify-2fa` (and `/elevate/verify-2fa`)
   takes the app's code, or a recovery code, in `2FACode`; no code is
   mailed. Each app code works once, and wrong codes use up the same
   attempt budget as mailed ones.

`/elevated/totp/recovery-codes` replaces the recovery codes, and
`/elevated/totp/disable` removes the app: an account that requires 2FA goes
back to mailed codes. Deleting the account removes it too. Use
`PostgresTotpStore` in production (its tables are in the migrations); the
secrets are login credentials, so keep that database encrypted at rest.

### Password policy

Every password is 8 to 256 characters. `.password_policy(policy)` adds
rules of your own for every new password (signup, password change, reset):
implement `PasswordPolicy::check(email, password)` and return
`PasswordRejected(message)` to refuse, which answers `400` with the
message. A refused reset password leaves the link usable.
`BreachedPasswordCheck` (feature `breached-passwords`) refuses passwords
found in data breaches, using the Have I Been Pwned range API: only the
first five hex digits of the password's SHA-1 are sent, and the reply is
padded. If the API cannot be reached the password is accepted.

### Rate limits

`.rate_limited(RateLimiter::new(store))` on the scheme limits how often the
routes an attacker would hammer may be tried: logins (password, passkey,
OAuth start), 2FA codes, `/elevate`, password reset, and the routes that
send a verification mail (signup, resend). Each group has a limit per
account (the address the request names, or the logged-in user) and per
client address; over either, the route answers `429` with `Retry-After`
and does nothing. Every attempt counts, right or wrong, so a `429` says
nothing about whether an account exists.

The defaults (`RateLimits::default()`) are 10 logins, 2FA codes or
elevations per account per 15 minutes (100 per client), and 5 reset or
verification mails per account per hour (30 per client). Change them with
`RateLimits::none().per_account(group, Some(Limit::new(max, window)))` and
`.per_client(...)`, passed to `.limits(...)`.

Count in `RedisRateLimitStore` in production (`HashMapRateLimitStore`
counts per process). The client address comes from the connection when you
serve with `AuthService::run`. Behind a reverse proxy that is the proxy:
pass `.client_address(|parts| ...)` reading the header your proxy sets
(and overwrites, so clients cannot forge it). IPv6 clients count per /64.
If the counter store is down, attempts are let through and the error is
logged.

### Customising

- **Mail.** Every message the library sends is a typed `Mail` (sign-in or
  elevation code, reset token, verification token, already-registered
  notice, email-login code and link). Override `EmailClient::send_mail` to
  write your own (HTML, the user's language, a link into your app instead
  of a raw token); the default renders `Mail::subject` and `Mail::text`
  through `send_email`.
- **Audit events.** `.auth_events(sink)` reports every library request to
  your `AuthEventSink`: `{ route, status, account, client }`, for an audit
  log, alerts on repeated failures or a "new sign-in" email. The request
  waits for `record`, so hand slow work off.
- **After-the-response jobs.** `.deferred_runner(runner)` runs the reset,
  signup and sign-in mails on your executor or job system instead of
  `tokio::spawn`. To never lose one on a restart, have `send_mail` put the
  message on a durable queue.
- **JWT claims.** `JwtScheme::jwt_claims(provider)` adds your claims
  (roles, tenant) to every JWT under `ext`, at issue and refresh; handlers
  read `Claims::ext`.

### Observability

Every library request runs in a `tracing` span, `tempered.route`, with the
route and (when it ends) the status; the OAuth and passkey flows have spans
of their own. Nothing secret or identifying goes into them: no addresses,
codes or tokens. With the `metrics` feature, the library also counts
through the [`metrics`](https://docs.rs/metrics) facade (install the
exporter you use, Prometheus or otherwise): `tempered_requests_total`
with `route` and `status`, and `tempered_rate_limited_total` with `group`.

### Mail sent after the response

Signup and password-reset initiation answer the same whether or not the
address has an account. They also take the same time, because everything that
depends on the account happens after the response: looking it up, storing the
token, and sending the mail. Those jobs run on the Tokio runtime (`tokio::spawn`)
and are bounded at 64 in flight per capability (`MAX_DEFERRED_JOBS`). When the
limit is reached, new jobs are dropped and logged; they are not run inline,
since that would bring the timing difference back under load. A job still
running when the process stops is lost, and the user asks again. Failures are
logged, never returned.

## Swapping implementations

Every moving part is a trait, so you choose the backend:

- **User store:** `HashMapUserStore` (dev) or `PostgresUserStore` (Argon2id).
  `.with_hasher(Argon2Hasher::new(params).max_concurrent(n))` sets the costs
  and how many hashes run at once (default: one per core, so a login flood
  queues instead of exhausting memory). After a cost change, each stored
  hash is upgraded at its owner's next login. A store of your own can use
  `Argon2Hasher` too.
- **Banned-token store:** `HashSetBannedTokenStore` (dev) or `RedisBannedTokenStore`.
- **Passkey verifier:** `WebAuthnRsVerifier` (feature `passkeys-webauthn`,
  off by default because `webauthn-rs` links OpenSSL):
  `WebAuthnRsVerifier::new("example.com", "https://example.com", key)?`,
  where `key` is at least 32 secret random bytes that turn each email into
  an opaque WebAuthn user handle. Keep the key stable: a new one changes
  every handle, and passkeys enrolled under the old one stop working. For
  more origins or a timeout, build a `webauthn_rs::Webauthn` (re-exported)
  and use `WebAuthnRsVerifier::from_webauthn`. Passkeys always require user
  verification (PIN or biometrics).
- **Token-epoch store** (revoke-all on password change / account deletion):
  `HashMapTokenEpochStore` (dev) or `RedisTokenEpochStore`.
- **Capability stores:** every store has an in-memory `HashMap*` (dev) and a
  production implementation:
  - Redis: `RedisSessionStore`, `RedisTwoFaCodeStore`,
    `RedisPasswordResetTokenStore`, `RedisEmailVerificationTokenStore`,
    `RedisOAuthStateStore`, `RedisChallengeStore` (passkey ceremonies).
  - Postgres: `PostgresOAuthIdentityStore`, `PostgresPasskeyCredentialStore`,
    `PostgresApiKeyStore`.

  A session scheme with elevation keeps two kinds of session; on one Redis,
  give the elevated store its own namespace
  (`RedisSessionStore::with_namespace(conn, ttl, "elevated")`). Each session
  also records which kind it is, so a login session is never accepted as
  an elevated one, even from a shared store.

  The Redis stores take a `redis::aio::ConnectionManager`. Build one with
  `ConnectionManager::new(redis::Client::open(url)?).await?` and clone it into
  each store: it is one multiplexed, auto-reconnecting connection, so no lock
  or pool is needed.
  The Redis stores need Redis 6.2 or later (`GETDEL`/`GETEX`), and the one
  holding the email-verified mark must persist (AOF/RDB). The Postgres stores'
  tables are in `src/tempered_adapters/migrations/`; like `PostgresUserStore`,
  the stores do not run them, so migrate at startup.

  Addresses are lowercased when parsed into an `Email`, so every store keys
  on the lowercase form. Rows written by versions before this change keep
  their original case and are no longer found by a lookup. Lowercase them
  yourself, merging any accounts that differ only in case first.
- **Email client:** `MockEmailClient`, `PostmarkEmailClient`, or your own `EmailClient`.
- **Token strategy:** JWT and session are both `CredentialScheme`s over a
  `TokenStrategy`; implement the trait to add a new token type.

> The in-memory `HashMap*`/`HashSet*` stores are for development and tests only.
> Several keep secrets unhashed and without expiry — use the Postgres/Redis
> stores in production.

## Writing your own store

Every store is a trait in `tempered::core` (`UserStore`, `SessionStore`,
`RefreshTokenStore`, ...), with its promises (atomic steps, single use,
owner scoping) in its docs. With the `testing` feature,
`tempered::testing` has one contract test per port, the same ones the
built-in stores pass:

```rust,ignore
#[tokio::test]
async fn my_store_keeps_the_promises() {
    tempered::testing::session_store(MySessionStore::connect().await).await;
}
```

## Examples

Runnable, self-contained (offline) examples live in [`examples/`](examples/):

```bash
cargo run -p tempered-example-jwt       # full JWT service + bundled frontend
cargo run -p tempered-example-session   # the same with server-side sessions (Redis if REDIS_HOST_NAME is set)
cargo run -p tempered-example-oauth     # OAuth2/OIDC with an embedded mock provider
cargo run -p tempered-example-passkey   # WebAuthn/passkeys with a simulated authenticator
cargo run -p tempered-example-passkey --features webauthn   # real passkeys in your browser
cargo run -p tempered-example-api-key   # API-key scheme
cargo run --example composed_scheme     # JWT for people + API keys for services on the same routes
```

Each opens on <http://localhost:3000>.

## Workspace layout

- `tempered_core` — domain types, capability traits, and ports (store/email traits).
- `tempered_adapters` — schemes (`JwtScheme`, `SessionScheme`, `ApiKeyScheme`),
  token strategies, and concrete store/email/OAuth/passkey backends.
- `tempered_axum` — the axum adapter: `auth_service` mounts the scheme's
  route table, plus the tier checks for your own routers.

The routes themselves (which exist, where, behind which check) come from the
framework-neutral route table in `tempered_adapters::endpoints`, so an
adapter for another web framework needs no per-capability code (see
ARCHITECTURE.md, "Adding a web-framework adapter").
- `tempered` — a facade crate that re-exports the common surface.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Unless you explicitly state
otherwise, any contribution intentionally submitted for inclusion in this
crate by you, as defined in the Apache-2.0 license, shall be dual licensed
as above, without any additional terms or conditions.
