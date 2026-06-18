# Plan: OAuth2 + Session + API Key + Passkeys alongside JWT

> Status: proposed. Target schemes alongside the existing `JwtScheme`:
> **OAuth2/OIDC, server-side Sessions, API keys, Passkeys (WebAuthn)**.
>
> **Coexistence decision:** `auth_service<S>` keeps taking exactly **one** scheme.
> Running several methods in one app is a *user* concern: they implement
> `AuthenticationScheme` + capability/validator traits on their own enum and
> control dispatch / validator try-order. The library ships **no** composite
> scheme. See [Phase 5](#phase-5--composition-is-a-user-concern) and
> `examples/composed_scheme.rs`.

## Implementation status (updated)

Framework-agnostic cores for all four schemes are **implemented, compiling, and
unit-tested** (47 adapter unit tests pass). Per the project's "composition is a
user concern" decision, OAuth and Passkeys are exposed as `*Flow` orchestrators
that **yield a verified `Email`** rather than issuing tokens themselves.

| Phase | Implemented | Deferred |
|---|---|---|
| 2 Session | `SessionScheme` + `SessionValidator` + `SessionStore` port + `HashMapSessionStore`; drops into `auth_service`. 3 tests. | `RedisSessionStore`; logout-everywhere route. |
| 3 API key | `ApiKeyScheme` + `ApiKeyValidator` (header/Bearer) + `ApiKeyStore` + `HashMapApiKeyStore` + `SupportsApiKeyIssuance` (SHA-256, constant-time). 5 tests. | HTTP issuance routes; Postgres store. |
| 1 OAuth2 | `OAuthFlow` (authorize-URL, CSRF state **bound to the browser via cookie**, code exchange, userinfo, identity link) + `OAuthHttpClient`/state/identity ports + `ReqwestOAuthHttpClient` + HashMap stores. 5 tests. | **PKCE** (`code_verifier`/`code_challenge`); authorize/callback axum routes; Redis/Postgres stores. |
| 4 Passkeys | `PasskeyFlow` (register + authenticate ceremonies, sign-count anti-clone) + `PasskeyCredentialStore`/`ChallengeStore`/`WebAuthnVerifier` ports + HashMap stores. 4 tests. | `webauthn-rs` adapter for `WebAuthnVerifier`; ceremony routes; client JS. |

Key design note: OAuth's provider HTTP and Passkeys' WebAuthn crypto are both
behind **ports** (`OAuthHttpClient`, `WebAuthnVerifier`), so the orchestration is
fully testable offline and the heavy/external dependencies stay out of the core
library. `sha2` was the only new dependency added.

## 0. The repeatable recipe

Every scheme lands in the codebase by filling the same slots:

| Slot | Location | Existing example to copy |
|---|---|---|
| Capability trait | `tempered_core/src/strategies/authenticator.rs` | `SupportsTwoFactor`, `SupportsPasswordReset` |
| Port(s) + errors | `tempered_core/src/ports/repositories.rs` | `TwoFaCodeStore`, `PasswordResetTokenStore` |
| Domain types | `tempered_core/src/domain/` | `TwoFaCode`, `PasswordResetToken` |
| Scheme method impl | `tempered_adapters/src/authentication/` | `JwtScheme` impls |
| Stores (test + prod) | `tempered_adapters/src/persistence/` | `HashMap*` + `Redis*`/`Postgres*` |
| Framework-agnostic handler | `tempered_adapters/src/handlers/` | `handle_initiate_password_reset` |
| Axum route | `tempered_axum/src/routes/` | `routes/initiate_password_reset.rs` |
| Capability-gated builder combinator | `tempered_axum/src/route_config.rs` + `auth_service.rs` | `with_password_reset`, `with_2fa` |

Notes:
- Capability is a *separate trait*, so each new builder method is bounded
  `where R::Scheme: SupportsX` — a scheme lacking a feature can't call it.
- Three of the four new schemes deliver tokens differently from JWT
  (OAuth = redirect, API key = JSON body, session = opaque cookie). All are
  expressible through the existing `ResponseBuilder`
  (`.status(302).metadata("location", url)`, `.json_body(..)`), so **no new
  builder type is required** — only new scheme methods + routes.

## Phase 0 — Cross-cutting foundation (do first)

- **0a. Generalize single-use email-token stores.** Password-reset,
  email-verification and (incoming) magic-link/recovery are near-duplicate
  `token → email, single-use, TTL` stores. Introduce one parameterized
  `SingleUseTokenStore` keyed by a `TokenPurpose` enum and make the existing
  three thin aliases. *Optional; prevents further duplication.* (~0.5d)
- **0b. HTTP delivery variants.** Add two small core traits mirroring
  `HttpAuthenticationScheme`:
  - `HttpOAuth2Scheme` → `create_authorize_redirect(builder, url, state_cookie)`,
    `create_callback_response(builder, token)`.
  - `HttpChallengeScheme` (Passkeys) → `create_challenge_response(builder, challenge_json)`.
  API keys and sessions reuse `HttpAuthenticationScheme` (body / cookie). (~0.5d)
- **0c. Config + deps.** Add `oauth2`, `webauthn-rs`, `base64` to the workspace.
  Extend config with provider secrets and per-scheme toggles. (~0.5d)

## Phase 1 — OAuth2 / OIDC (social login)  ~2–3d

`SupportsOAuth2` already exists in core but is unimplemented; revise it so
`begin` also returns a `state`/PKCE verifier and `complete` takes `(code, state)`.

- **Domain:** `OAuthProvider`, `OAuthIdentity { provider, subject }`, `OAuthState`.
- **Ports:** `OAuthIdentityStore` (`link`, `find_user_by_identity`);
  `OAuthStateStore` (CSRF state + PKCE verifier, single-use TTL — can reuse 0a).
- **Scheme:** `OAuth2Scheme` config = client id/secret, auth/token/userinfo URLs,
  scopes, redirect URI. `begin` builds the authorize URL + stores state;
  `complete` exchanges the code (`reqwest`), fetches userinfo, upserts the user,
  then **issues the existing JWT** so downstream is identical to password login.
- **Routes:** `GET /oauth/{provider}/authorize` (302), `GET /oauth/{provider}/callback`.
- **Builder:** `with_oauth2(providers)` gated on `HttpOAuth2Scheme`.
- **Security:** mandatory `state` + PKCE, exact `redirect_uri` match, OIDC
  `iss`/`aud`/`nonce` validation.

## Phase 2 — Server-side sessions (opaque cookie, Redis)  ~1.5d

Stateful counterpoint to JWT — instantly revocable, mutable session data.

- **Domain:** `SessionId` (CSPRNG, 256-bit), `Session { user, created, last_seen, csrf }`.
- **Port:** `SessionStore` (`create`, `get`, `touch` sliding expiry, `delete`,
  `delete_all_for_user`). Test `HashMapSessionStore` + prod `RedisSessionStore`.
- **Scheme:** `SessionScheme` — login verifies password via `UserStore`, creates a
  session, returns the opaque id in an HttpOnly cookie. Validator looks up the
  session, enforces idle + absolute timeout, touches it. Logout = delete
  (true revocation; reuses `SupportsTokenRevocation`).
- **Routes/builder:** fits `HttpAuthenticationScheme` as-is — login/logout/
  verify-token need no new routes. Add optional `delete_all_sessions`
  (logout-everywhere) validated route.

## Phase 3 — API keys (machine-to-machine)  ~1.5d

The case `HttpAuthenticationScheme`'s docs anticipate (token in header, not cookie).

- **Domain:** `ApiKey` (`prefix.secret`), `ApiKeyId`, `Scope`.
- **Port:** `ApiKeyStore` — store only a **hash** (Argon2); `create`,
  `find_by_prefix`, `revoke`, `list_for_user`. Test + Postgres impls.
- **Scheme:** `ApiKeyScheme` — keys are *issued*, not "logged in". Validator reads
  `Authorization: Bearer` / `X-API-Key`, splits prefix, hash-compares, returns
  claims (key id, owner, scopes).
- **New capability:** `SupportsApiKeyIssuance` (`create`/`revoke`/`list`).
  Plaintext returned **once** at creation.
- **Routes:** `POST /api-keys`, `GET /api-keys`, `DELETE /api-keys/{id}` behind the
  validated (or elevated) router.

## Phase 4 — Passkeys / WebAuthn (FIDO2)  ~3–4d  🔶 primary-login assumption

Built on `webauthn-rs`. Two ceremonies, each a challenge→response round-trip.

- **Domain:** `PasskeyCredential { cred_id, public_key, sign_count, user }`,
  `WebauthnChallenge`.
- **Ports:** `PasskeyCredentialStore` (register/list/update sign-count per user) +
  short-TTL `ChallengeStore` (reuse 0a/state store).
- **Scheme:** `PasskeyScheme` wrapping a `Webauthn` instance.
  - Register: `POST /passkeys/register/start` + `/finish` (verify attestation, store).
  - Authenticate: `POST /passkeys/login/start` (challenge via `HttpChallengeScheme`)
    + `/finish` (verify assertion, bump sign-count, **issue JWT**).
- **New capability:** `SupportsWebAuthn`.
- **Client:** needs JS `navigator.credentials` ceremony — the `assets/` SPA gains a
  passkey button. The one scheme with mandatory front-end work.
- 🔶 If Passkeys should be **step-up / 2FA** rather than primary login, it instead
  plugs into the existing elevation/2FA machinery and shrinks to ~2d.

## Phase 5 — Composition is a user concern  ~1d

No library composite. `auth_service<S>` stays single-scheme. A user wanting
several methods implements the traits on an enum and owns dispatch + the
multi-validator try-order. See `examples/composed_scheme.rs` for the worked
skeleton.

**Two ergonomics rules to hold while building Phases 1–4:**
1. Every scheme exposes its `Token`, `Validator`, `Claims`, and error types as
   **public, nameable types** (so they can be wrapped in a user enum). JWT
   already does this — keep the line.
2. Keep every validator's `RequestParts = http::request::Parts` (uniform), so a
   user's enum validator can try them in sequence.

**Credentials disambiguation convention (decide now):** a user's `MyCredentials`
enum needs a serde strategy so `login` can parse a body and route to the right
variant. Recommended: an internally-tagged `"method"` discriminator
(`#[serde(tag = "method")]`) over `#[serde(untagged)]` (clearer errors, no
ambiguous matches).

## Testing strategy (per phase)
- **Unit** (colocated, like `local_jwt_validator` tests): parsing, validator
  accept/reject, expiry, revocation.
- **Integration** (`tempered_axum/tests/api/`, one file per endpoint,
  `testcontainers` Postgres/Redis): full HTTP flows. OAuth uses `wiremock` to fake
  the provider; Passkeys uses `webauthn-rs` software-authenticator test helpers.
- **Security cases:** OAuth state/PKCE mismatch, API-key timing, session fixation,
  passkey sign-count regression, email-enumeration on every "initiate" endpoint.

## Sequencing & effort (~10–13 dev-days)
1. Phase 0 foundation (~1.5d) — gates the rest
2. Phase 2 Session (~1.5d) — warm-up, reuses most machinery
3. Phase 3 API key (~1.5d)
4. Phase 1 OAuth2 (~2–3d)
5. Phase 4 Passkeys (~3–4d)
6. Phase 5 composed example + docs (~1d)

Phases 1–4 are independent and parallelizable.

## Open decisions
1. **Passkeys role** — primary login (planned) vs. step-up/2FA (smaller). 🔶
2. **First OAuth providers** — Google + GitHub assumed; affects OIDC-vs-plain handling.
3. **Phase 0a token-store generalization** — now, or defer and accept duplication.
4. **Credentials tag convention** — confirm `#[serde(tag = "method")]`.
