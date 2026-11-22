# Follow-up Plan

Fixes for the findings of the 2026-11-16 codebase analysis. Baseline at the time
of writing: `feat/additional-auth-schemes` @ `398754b`, 128 tests passing, about
40 clippy warnings, branch not pushed.

Convention: one well-described commit per task/subtask.

Order: Phase 0 first (it is a live exposure), then 1 → 2 → push + PR to `main`.
Phases 3–5 are feature work and go in as separate PRs afterwards, so the 56
commits already on this branch are not held behind them.

---

## Phase 0 — Leaked secrets ✅ DONE (2026-11-22: the owner confirmed the leaked values were dummy secrets, so 0.1 needs no rotation)

`.env` is tracked, and it is on `origin/main` of a **public** GitHub repo (11
commits touch it, 2025-09-05 → 2025-09-24). It holds `JWT_SECRET`,
`JWT_ELEVATED_SECRET` (86 chars each) and a UUID-shaped `POSTMARK_AUTH_TOKEN`.
Treat all three as compromised regardless of what is done to git.

- **0.1 Rotate (owner action, outside the repo).** Revoke the Postmark server
  token and issue a new one. Replace both JWT secrets anywhere they are deployed
  (the droplet behind `DOMAIN_URL`). Change `POSTGRES_PASSWORD` if the deployed
  database uses the committed value.
- **0.2 Untrack.** `git rm --cached .env`; add a `.env.example` with key names
  and dummy values. `.gitignore` already lists `/.env`.
  Commit: `fix(security): stop tracking .env, add .env.example`.
- **0.3 Remove the deploy host from the Justfile.** `connect: ssh root@<ip>`
  publishes the server address and that root login is in use. Folded into 1.3.
- **0.4 History rewrite (optional, needs explicit go-ahead).** `git filter-repo
  --path .env --invert-paths` plus a force-push of every remote branch. This
  rewrites public history and does not un-leak anything already cloned or
  scraped, so rotation (0.1) is what actually closes the hole. Recommendation:
  rotate, untrack, skip the rewrite unless a clean history matters to you.

---

## Phase 1 — Stale docs and housekeeping ✅ DONE

- **1.1 README quickstart compiles again.** It calls `JwtScheme::new` with three
  arguments and builds `JwtAuthConfig` without `audience` / `issuer`; the real
  constructor needs a fourth `TokenEpochStore` argument. Fix the snippet and
  import everything from the facade (`tempered::auth_service`) instead of
  `tempered_axum`.
  To stop it rotting again, move the snippet into `examples/quickstart.rs` (built
  by `cargo check --all-targets`) and have the README mirror that file.
  Commit: `docs(readme): fix quickstart and back it with a compiled example`.
- **1.2 Rewrite `CLAUDE.md`.** It still describes `auth-service` / `app-service`
  / Caddy. Replace with the 3-crate layout, the real commands (`cargo test
  --workspace`, the example packages, Docker needed for the API tests), and
  pointers to `ARCHITECTURE.md`. Note: `.gitignore` lists `/CLAUDE.md` while the
  file is tracked — drop the ignore line.
  Commit: `docs(claude): describe the library workspace, not the bootcamp services`.
- **1.3 Rewrite the `Justfile`.** Every recipe points at directories that no
  longer exist. Keep `generate-secret`; replace the rest with `test`, `lint`,
  `example <name>`, `db-up` / `db-down` (using `examples/jwt_standalone/compose.yml`).
  Remove `connect`.
  Commit: `chore(just): replace bootcamp recipes with workspace recipes`.
- **1.4 Remove bootcamp leftovers** after confirming nothing references them
  (a grep found no references): `api_schema.yml`, `Authentication Service
  API.postman_collection.json`, root `config/config.json`, root `build.rs`
  (watches a `migrations/` dir that does not exist at the root), and the
  duplicate `src/tempered_axum/migrations/` (byte-identical to the adapters copy;
  point `tests/api/helpers.rs` at `../tempered_adapters/migrations`).
  One commit per removal group.
- **1.5 Mark `docs/AUTH_SCHEMES_PLAN.md` with its real status** (what shipped,
  what moved to this plan), matching how `REVIEW_CORRECTION_PLAN.md` is kept.

---

## Phase 2 — Lint and CI ✅ DONE (CI not yet run on GitHub)

- **2.1 Clippy to zero.** `cargo clippy --fix` handles about 29 of the warnings
  (needless borrows, `Ok(x?)`, collapsible `if`, `matches!`). By hand:
  - six "very complex type" warnings → named `type` aliases;
  - `tests/api/helpers.rs:122` `let _ = tokio::spawn(..)` → keep the
    `JoinHandle` on the test app or `drop` it explicitly;
  - unused `status` / `message` fields in the `verify_2fa` test struct.
  Commits: one for the mechanical `--fix`, one for the manual ones.
- **2.2 Delete the deprecated `AuthResponseBuilder`.** It is an empty alias
  trait in `http_abstraction.rs:255`, re-exported at `tempered_core/src/lib.rs:51`
  and mentioned in two `adapters.rs` doc comments. Pre-1.0, so remove rather than
  keep the shim. Commit: `refactor(core): remove deprecated AuthResponseBuilder`.
- **2.3 Fix `.cargo/config.toml`.** The `check` alias is ignored (cargo refuses
  to shadow a built-in). Rename to `lint`, keep `clippy-strict`.
- **2.4 CI that covers this work.** In `.github/workflows/prod.yml` (rename to
  `ci.yml`):
  - trigger on `pull_request` as well as pushes to `main`;
  - `actions/checkout@v4`, `Swatinem/rust-cache@v2` instead of the hand-rolled
    cache; drop the unused `cargo install sqlx-cli` step (several minutes per run);
  - jobs: `cargo fmt --check`, `cargo clippy --workspace --all-targets
    --all-features -- -D warnings`, `cargo test --workspace` (testcontainers
    works on `ubuntu-latest`), and `cargo check -p tempered --no-default-features`
    to guard the lean build;
  - delete the commented-out bootcamp deploy steps.
  Commit: `ci: run fmt, clippy, tests and the lean build on PRs`.

### Phases 0–2 as executed (2026-11-16, commits `8c693fc..6972e91`)

Result: 0 clippy warnings under `-D warnings`, `cargo fmt --check` clean, 128
tests passing, lean build verified. Deviations from the plan as written:

- **0.1 is not done.** Untracking `.env` does not revoke anything; the Postmark
  token and both JWT secrets are still in public history until rotated.
- **1.1** also corrected the README's claim that every capability store has a
  Redis/Postgres implementation (only 2FA codes and reset tokens do).
- **1.4** also removed `src/tempered_adapters/config/config.json` (a second
  unreferenced copy).
- **1.5** surfaced a gap the analysis missed: OAuth PKCE was never implemented.
  Added as task 3.0.
- **2.1** four of the six "very complex type" warnings are typestate builder
  return types, where an alias would hide which slot changes; those carry
  `#[allow(clippy::type_complexity)]` with a reason. The two `fn`-pointer hooks
  in `route_config.rs` got aliases. The two core `PartialEq` impls now compare
  discriminants.
- **2.1** added a workspace-wide `cargo fmt` commit (51 files, formatting only)
  so CI can enforce `fmt --check`.
- **2.4** the lean job also greps `cargo tree` so sqlx/redis/reqwest cannot
  leak back into the no-default-features build. The workflow has only been
  validated locally (YAML parse + each command run by hand); its first real run
  is the PR.

**Then:** push the branch, open the PR to `main`, merge.

---

## Phase 3 — Production stores for the new schemes ✅ DONE (2026-11-20)

As built: `RedisSessionStore`, `RedisOAuthStateStore`, `RedisChallengeStore`,
`RedisEmailVerificationTokenStore`, `PostgresOAuthIdentityStore`,
`PostgresPasskeyCredentialStore`, `PostgresApiKeyStore`, one commit each, with
three migrations and refreshed `.sqlx/`. Every port has one contract test in
`persistence::contract`, run against both its in-memory and its production
store (Redis 7 / Postgres containers). Choices made on the way:
- The Redis stores need Redis 6.2+ (`GETDEL`, `GETEX`); the tests pin 7.4,
  since the testcontainers default image is older.
- Per-user Redis sets index sessions, passkey ceremonies and pending
  verification tokens, written in the same transaction as the entry. The
  session revocation counter never expires.
- The verified mark lives in Redis without a TTL: that Redis must persist.
- The sign-count rule is now part of `PasskeyCredentialStore`: an update that
  does not advance the counter (unless both are 0) fails with the new
  `PasskeyStoreError::SignCountNotAdvanced`, atomically (one conditional
  `UPDATE` in Postgres, under the write lock in memory). A concurrent test
  checks that exactly one of 16 replays wins.
- `PostgresApiKeyStore` keeps ids as text; scopes are `TEXT[]`.

Original plan:

Seven ports have only a `HashMap*` implementation. Split by data lifetime:

| Port | Backend | Why |
|---|---|---|
| `SessionStore` | Redis | TTL-bound, read on every request |
| `OAuthStateStore` | Redis | minutes-long, single-use (`GETDEL`) |
| `ChallengeStore` | Redis | minutes-long, single-use |
| `EmailVerificationTokenStore` | Redis | TTL-bound, single-use; mirrors the reset-token store |
| `ApiKeyStore` | Postgres | durable, listed per owner, looked up by prefix |
| `OAuthIdentityStore` | Postgres | durable account link, unique on (provider, subject) |
| `PasskeyCredentialStore` | Postgres | durable, sign-count updated per login |

- **3.0 Settle the port shapes before writing stores.** Two ports are expected
  to change, and a store written first would be written twice:
  - ✅ DONE (2026-11-17). **OAuth PKCE is not implemented** (found while updating
    `AUTH_SCHEMES_PLAN.md`; the port doc at `repositories.rs:269` already calls
    it out). Add `code_challenge` (S256) to the authorize URL and send
    `code_verifier` on the code exchange; the verifier is stored with the state,
    so `OAuthStateStore` gains a payload. Update `OAuthFlow`,
    `HashMapOAuthStateStore`, `OAuthHttpClient::exchange_code`, the mock
    provider in `oauth_axum`, and add a verifier-mismatch test.
    Commit: `feat(security): add PKCE (S256) to the OAuth flow`.
    As built: `store_state(state, code_verifier: Secret<String>)` and
    `consume_state(state) -> Secret<String>`, so the Redis store holds one
    value per state key and `GETDEL` gives single-use for free. `pkce_challenge_s256`
    is public (facade re-export) for mock/test providers. New dep: `base64`.
  - `ChallengeStore` — see 4.1.
- Redis stores follow `redis_password_reset_token_store.rs`; Postgres stores
  follow `postgres_user_store.rs` and each ships an up/down migration in
  `src/tempered_adapters/migrations/` plus refreshed `.sqlx/` offline data.
- Each store: gated behind the existing `redis` / `postgres` feature,
  re-exported from the facade, tested against testcontainers with the same
  cases as its `HashMap*` twin. Where practical, lift those cases into one
  shared contract-test function per port so both impls run the same assertions.
- Things to get right: session lookup by user for `delete_all_for_user` (a
  per-user Redis set alongside the session keys); atomic single-use consumption
  for state/challenge/verification tokens; the passkey sign-count update must be
  a conditional `UPDATE ... WHERE sign_count < $new` so a replayed assertion
  cannot win a race.
- One commit per store (seven), Redis ones first.

---

## Phase 4 — Real WebAuthn verifier

No production `WebAuthnVerifier` exists; the only impls are two test mocks and
the example's `DemoVerifier`.

- **4.1 Port check first (design risk).** ✅ DONE (2026-11-17), confirmed against
  the `webauthn-rs` 0.6.2 docs; see "Port changes as executed" below.
  Original note: The port takes a challenge generated
  by `PasskeyFlow` and is synchronous and stateless. `webauthn-rs` generates its
  own challenge and returns an opaque state object (`PasskeyRegistration` /
  `PasskeyAuthentication`) that must be stored between start and finish. These
  do not line up. Expected change: the verifier's `start_*` returns
  `(options_json, opaque_state)`, `ChallengeStore` stores the opaque state, and
  `verify_*` takes it back. Confirm against the current `webauthn-rs` docs
  before touching the trait; update `PasskeyFlow`, both mocks, `DemoVerifier`
  and the Phase 3 `ChallengeStore` in the same commit.
  If 4.1 changes `ChallengeStore`, do it before the Redis `ChallengeStore` in
  Phase 3.
  As built: the verifier owns the challenge. `start_*` returns
  `CeremonyStart { options, state: CeremonyState }`; `PasskeyFlow` parks the
  opaque state in `ChallengeStore` under a server-generated `CeremonyId` and
  returns `PasskeyCeremony { ceremony_id, options }`; `finish_*` gets the state
  back. `PasskeyCredential.public_key` became opaque `credential_data` (for
  `webauthn-rs`: the serialized `Passkey`), and `VerifiedAssertion` can return
  replacement data, persisted via
  `PasskeyCredentialStore::update_after_authentication`. HTTP shape: start
  returns `{ ceremony_id, options }`, finish takes `{ ceremony_id, response }`.
  Notes for 4.2: serializing `webauthn-rs` ceremony state needs its
  `danger-allow-state-serialisation` feature; `start_passkey_registration`
  wants a `Uuid` user handle (derive one from the email, e.g. UUIDv5);
  usernameless login needs its `conditional-ui` feature.
- **4.2 `WebAuthnRsVerifier`** in `tempered_adapters/src/passkey/`, behind a new
  `passkeys-webauthn` cargo feature (default-off: it pulls OpenSSL-class
  dependencies). Tested with the `webauthn-authenticator-rs` software
  authenticator, including the sign-count-regression case.
- **4.3 Real browser example.** `passkey_axum` gets a second mode using the real
  verifier and `navigator.credentials` JS in `assets/index.html`; the simulated
  mode stays for offline runs.

---

## Phase 5 — Examples

- **5.1 Finish `examples/composed_scheme.rs`.** Replace the six `todo!()`s with
  a working JWT + API-key enum scheme and a multi-try validator, per the
  "composition is a user concern" decision. Add an oneshot test so it stays
  honest.
- **5.2 `examples/session_axum`.** A `SessionScheme` twin of `jwt_standalone`;
  uses the Redis `SessionStore` from Phase 3 when `REDIS_HOST_NAME` is set and
  the in-memory one otherwise. Add it to the README example list.

---

Phases 6–10 come from the multi-agent review of 2026-11-21 (`main` @
`df1acb1`): two security reviewers, one logic-bug reviewer, one architecture
reviewer and one gap analysis, with the high-impact findings checked by hand.

## Phase 6 — Security pass ✅ DONE (2026-11-21, `9d74370..6a77bc4`)

One commit per task. Each comes with a test that fails before the fix.

As executed:
- 6.8 and 6.9 are one commit (`f59c0c5`): they are one Lua script.
  `TwoFaCodeStore::validate` became `redeem_code`. Codes stored before
  the change read as absent, so those users log in again.
- An extra commit (`fc666af`) came from the automated commit review: the
  reset, verification and challenge stores purged a user's index set in
  two steps, so a token stored in between survived. They now use one
  script (`redis_support::purge_index`).
- 6.6 also stopped `complete_password_reset` reporting a store outage as
  an invalid link.
- New shared contract tests: `user_store`, `password_reset_token_store`,
  `two_fa_code_store`, `token_epoch_store`.
- Startup panics on misconfiguration: JWT secret < 32 bytes, an elevated
  JWT config with the primary secret, and an OAuth endpoint that is not
  https off the loopback.

- **6.1 Case-fold email addresses.** `Email::try_from` keeps the address as
  given, so `Alice@x.com` and `alice@x.com` are two accounts. A provider
  login whose address differs only in case makes a second account and skips
  the pre-hijacking cleanup of the real one. Lowercase the whole address at
  parse time. Every store keys on `Email`, so this one change covers them
  all. Existing mixed-case rows are not migrated, because a lowercasing
  migration fails on duplicates. Say so in the README.
- **6.2 Revoke elevated sessions with the rest.** `SessionScheme`'s elevation
  uses its own session store, and password change, reset, deletion and
  `secure_unproven_account` only revoked the primary tokens. An elevated
  session also slides its expiry while used, so it survived a password reset
  and could set a new password. Add a private slot hook (like
  `PasskeyCleanup`) that revokes the elevation tokens wherever the primary
  ones are revoked. JWT already shares the epoch store; revoking twice is
  harmless.
- **6.3 Reset tokens die with the account and with credential changes.**
  Deletion and password change did not touch outstanding reset tokens. A
  token mailed before deletion reset the password of whoever re-registered
  the address within the hour. Add
  `PasswordResetTokenStore::delete_all_for_user` (a per-user set in Redis, as
  in the verification store) and call it on deletion, password change,
  completed reset and `secure_unproven_account`.
- **6.4 `PostgresUserStore::set_new_password` reports a missing user.** It
  ignored `rows_affected`, so a reset against a deleted account returned
  success. Return `UserNotFound` as the in-memory store does, and add a
  shared `UserStore` contract test.
- **6.5 API keys: owner-scoped revoke and per-owner cleanup.**
  `revoke_api_key(id)` had no owner check, so exposing it lets any user
  revoke anyone's key. Make it `revoke_api_key(owner, id)` and add
  `ApiKeyStore::delete_all_for_owner` for account deletion (`ApiKeyScheme`
  is a separate scheme, so the app calls it; document this).
- **6.6 No internal error text in responses.** `complete_password_reset`
  (unauthenticated), `change_password`, `delete_account`, `/elevate`, the
  passkey store errors and the API-key store errors sent `e.to_string()`,
  which can include sqlx or redis text. Answer with the classified message
  and log the cause.
- **6.7 JWT hardening.** jsonwebtoken's default 60 s `exp` leeway outlived the
  ban-list and epoch TTLs, so a revoked token could validate again for up to
  a minute. Set the leeway to 0. Reject secrets shorter than 32 bytes, and
  reject an elevated config with the same secret as the primary one.
- **6.8 Atomic 2FA checks in Redis.** The attempt cap was get-then-incr, so
  parallel guesses each got a try, and a correct code was validated and then
  deleted, so two concurrent submissions both logged in. Count the attempt
  and compare in one Lua script, and consume on success in the same script.
- **6.9 2FA budget survives a new login.** `store_code` reset the attempt
  counter, so an attacker with the password got 5 fresh guesses per login.
  Keep the counter across reissue for its own window.
- **6.10 OAuth HTTP client hardening.** `reqwest::Client::new()` had no
  timeouts and followed redirects. A 307/308 from the token endpoint would
  resend the code, verifier and client secret. Set connect and request
  timeouts and `redirect::Policy::none()`, and require `https` provider URLs
  (plain http only for loopback).
- **6.11 Atomic epoch cutoff in Redis.** `revoke_before` read and then wrote,
  so two instances racing could lower the cutoff. Do it in one Lua script.
- **6.12 Maximum password length.** Only a minimum (8) was enforced. Cap it
  at 128 bytes so a large body cannot make every Argon2 call expensive.

Raised by the review; they change behaviour, so each needs a decision
before it is built:
- ~~`/elevate` ignores `Requires2Fa`~~ ✅ DONE 2026-11-22: two-step
  elevate (`206` challenge, then `POST /elevate/verify-2fa`);
  `SupportsElevation::elevate` returns `LoginOutcome` and gains
  `verify_elevation_2fa`.
- Login-level `/change-password` needs no current password. **Decided
  2026-11-22: keep it that way.** The elevated tier is the re-authentication
  step. Apps that want it put password change behind elevation; the README
  says so.
- Account enumeration: signup answers 409 "User already exists", and reset
  initiation is slower for real accounts. A fix is to always answer the
  same, and mail an "already registered" notice.
- Passkey login skips 2FA. That may be intended (a passkey is possession
  plus user verification), but it should be documented either way.
- Sessions have no absolute lifetime. Store a created-at time and cap the
  age.
- Smaller items:
  - `PendingCeremony` does not record whether it is a registration or a
    login.
  - The `WebAuthnVerifier` port does not say what a verifier must check
    (raw id, user handle).
  - `ServeDir` serves dotfiles, so an `assets_dir` of `"."` would serve
    `.env`.
  - No `__Host-` cookie prefix and no Origin check.
  - Redis 2FA and reset stores map errors to "not found".
  - `authenticate_user` maps DB errors to `UserNotFound`.
  - An OAuth email change after linking locks the user out of that
    provider.
  - The OAuth callback rejects a provider `error=` redirect without
    clearing the state cookie.

## Phase 7 — Performance

- **7.1 Async Redis.** ✅ DONE 2026-11-22. All nine Redis stores take
  `Arc<RwLock<redis::Connection>>` and make blocking calls. Every request
  queues behind one connection, and each call blocks an executor thread.
  This includes the JWT epoch check on every authenticated request. Switch
  to `redis::aio::ConnectionManager` (clone it, no lock). This changes the
  constructors, which is fine before 1.0.
- **7.2 `Arc` the scheme.** axum clones `State<S>` per request, and the
  scheme holds `JwtAuthConfig`, strings and the secret, twice, by value. Hold
  the scheme or its config in an `Arc`.
- **7.3 Fewer round trips.**
  - Run the JWT ban and epoch checks concurrently.
  - Read and slide a Redis session in one `GETEX` instead of three
    commands.
  - Consider refreshing the session TTL only past half-life.
- **7.4 Bound Argon2.** Put a semaphore around `spawn_blocking` hashing so a
  login flood cannot fill the blocking pool (about 19 MiB each). Make the
  Argon2 parameters configurable and rehash on login when they change.

## Phase 8 — Missing features

Must-have for a working framework:
- **8.1 Rate limiting and lockout.** Add a `RateLimitStore` port (Redis +
  in-memory) and per-account and per-IP limits on `/login`, `/elevate`,
  `/verify-2fa`, reset, resend (absorbs the backlog item) and the passkey and
  OAuth starts. Answer 429 (`ErrorCategory::TooManyRequests` exists).
- **8.2 Real WebAuthn verifier**: Phase 4.
- **8.3 TOTP and recovery codes.** Today the only second factor is a code
  sent by email, and `requires_2fa` is a flag with no enrol route. Make the
  2FA slot a pluggable second factor (email, TOTP). Add a TOTP secret store,
  hashed recovery codes, and enrol/confirm/disable routes in the elevated
  tier.
- **8.4 OIDC.** Verify the ID token (JWKS, `iss`/`aud`/`exp`, nonce in
  `PendingAuthorization`) and read `.well-known` discovery. Add provider
  presets for Google, Microsoft and Apple, and GitHub with its emails
  endpoint. The README says "OIDC"; today it is OAuth2 plus userinfo.
- **8.5 CSRF defence in depth.** Add an `Origin` / `Sec-Fetch-Site` check on
  state-changing cookie routes. Today the only defence is `SameSite=Lax`
  plus JSON bodies.

Should-have:
- **8.6 Refresh tokens** with rotation and reuse detection, short-lived
  access JWTs, and an `Authorization: Bearer` mode for SPAs and mobile.
  Today JWTs and sessions are cookie-only.
- **8.7 Session and device management.** `SessionStore::list_for_user`,
  per-session metadata (created, last seen, user agent), and list/revoke
  routes.
- **8.8 Passwordless login**: magic links and email OTP, as a new slot over
  the existing token-store shapes.
- **8.9 Email change** (verify the new address, notify the old one,
  elevated). This needs 9.5 first.
- **8.10 Password policy** port and an optional breached-password check
  (HIBP k-anonymity, behind a feature).
- **8.11 Account self-service routes.** Link or unlink an OAuth provider
  while logged in, and list, rename or delete passkeys.
- **8.12 API-key management.** Issue/list/revoke routes in the elevated
  tier, scope enforcement (`require_scope`), expiry and last-used.
- **8.13 Observability.** `#[instrument]` spans on the flows, plus metrics
  counters behind a feature.

Nice-to-have: roles and organisations, admin APIs (ban, force reset,
impersonate), SMS OTP once 8.3 exists, risk signals, CAPTCHA hook.

Out of scope (state it in the README): being an OIDC/OAuth provider, SAML,
SCIM and enterprise SSO brokering. Integrate an external IdP through the
OAuth slot instead.

## Phase 9 — Extensibility and modularity

- **9.1 Readable errors for missing capabilities.** Add
  `#[diagnostic::on_unimplemented]` on the `Wire*` and `Supports*` traits.
- **9.2 Customisation ports.**
  - `EmailComposer`: typed messages, HTML, links rather than raw tokens,
    locale.
  - `AuthEventSink`: login ok/fail, 2FA, reset, link, delete, for audit
    logs and "new sign-in" emails. Default it to tracing; it is a
    constructor parameter.
  - Custom claims (roles, tenant) via the validator's `Claims` type.
- **9.3 Split `credential_scheme.rs`** (1,888 lines) into per-capability
  modules, keeping each slot's types and impls together.
- **9.4 Error sources.** Store errors carry `String`. Keep the underlying
  error as `#[source]` so callers can match unique-violation against
  connection failure.
- **9.5 Stable user id.** Every store keys on `Email`. A UUID with the
  (case-folded) email as a lookup index makes email change possible and
  simplifies cleanup. This touches every port (L).
- **9.6 Public contract tests.** Expose `persistence/contract.rs` behind a
  `testing` feature so third-party store backends can run them.
- **9.7 Capability bundle (only if more slots are planned).** A ninth slot
  touches about 36 impl headers that each spell out all eight generics. A
  `Capabilities` bundle with associated types would shrink them to
  `<U, T, C>`.
- **9.8 Framework-neutral routes** ✅ DONE 2026-11-22 (designed 2026-11-21). See `docs/ROUTE_TABLE_DESIGN.md`. A route table (`RouteId`,
  method, path, tier) and one `Endpoints::handle` dispatcher in
  `tempered_adapters` replace `wiring.rs`, `route_config.rs` and
  `routes/*`. Library routes are authorized inside the library, and a new
  framework adapter is about 300 lines. 8 commits; §10 of the design lists
  four decisions.

## Phase 10 — Release basics

Add a LICENSE, SECURITY.md, CHANGELOG, `rust-version` (MSRV) and
crates.io-ready Cargo metadata (description, repository, license, versioned
internal dependencies). Fuzz the token, cookie, API-key and WebAuthn JSON
parsers.

## Backlog

- **Configurable rate limit on `/verify-email/resend`** (requested
  2026-11-20). A logged-in user, including one squatting on someone else's
  address, can make the library mail that address as often as they like.
  Add a per-address limit (count per window, set on the email-verification
  builder) backed by a store port with Redis and in-memory implementations;
  over the limit, answer 429 without sending. Signup also sends a link, so
  the same limit should count those.

---

## Port changes as executed (2026-11-17, branch `feat/pkce-and-webauthn-port`)

Both port changes that had to precede the stores are done (3.0 PKCE, 4.1
verifier shape). Reading the passkey and elevation code for them surfaced
defects the earlier analysis had missed; each is fixed in its own commit:

- **Passkey enrolment was unauthenticated** (account takeover): the
  `register/*` routes were public and took the email from the body. Now behind
  the login middleware, enrolling for the session owner only; a ceremony can
  only be finished by the user who started it.
- **`/elevate` returned 500 for every `SessionScheme`**: the route named the JWT
  claims type. Routes now read the user through `IdentityClaims`.
- **Credential ids could be overwritten** by re-registering them
  (`add_credential` is now insert-only), and a login ceremony started for one
  user accepted another user's credential.
- **Passkeys outlived the account**: login now requires the account to exist,
  and `delete_account` removes the user's passkeys.
- **Two JWTs issued in the same second were identical**, so logout + immediate
  re-login gave a banned session. Tokens now carry a random `jti`.

CI also turned out to run a newer Rust (1.100) than local development (1.94);
main was fixed for it (`6404c50`, `815b10d`). Run `rustup update stable`, or
lint with `cargo +1.100.0`, before pushing.

Consequences for Phase 3: `OAuthStateStore` holds a verifier per state;
`ChallengeStore` holds a `PendingCeremony` (user + opaque bytes) per
`CeremonyId`; `PasskeyCredentialStore` needs insert-only `add_credential`
(primary key), `update_after_authentication` (counter + optional data) and
`delete_all_for_user`.

## Decisions settled 2026-11-17, and what was built

1. **Step-up for passkey enrolment — yes, as an option.** Done:
   `supports_elevation(.., |e| e.supports_passkey_enrollment())` moves the two
   enrolment routes to `/elevated/passkey/register/{start,finish}`. Default
   stays login-gated. Routes that can sit in either bucket are now generic over
   that bucket's claims type (`ElevatedBucketClaims` in `wiring.rs`), which also
   fixed `/elevated/change-password` and `/elevated/delete-account` returning
   500 for session schemes.
2. **OAuth login semantics.** Done: no account → create one (random,
   unknowable password) and log in; existing account → normal login (see the
   pre-hijacking decision below for the first login to an unproven account);
   account requires 2FA → challenge issued, no token, callback redirects to
   `.oauth_two_fa_redirect(path)?oauth_2fa=required` with the attempt id and
   email in a short-lived `oauth_2fa` cookie.
3. **OAuth identity links on account deletion** — deferred on 2026-11-17,
   then decided on 2026-11-18: removed with the account (see below).

Also fixed from review of these changes: each OAuth state is bound to the
provider it was issued for (`PendingAuthorization { provider, code_verifier }`
in `OAuthStateStore`); account deletion removes credentials before the account.

## Pre-hijacking decision (raised 2026-11-17, settled 2026-11-18)

**The problem.** With "existing account → normal login", an attacker could sign
up with the victim's email and a password they choose (signup does not prove
the address is theirs), wait for the real owner to log in through a provider,
and still hold a way into that account.

**Decision: secure the account on the first link, but only if its address was
never proven.** This is what Firebase Auth and Supabase Auth do. Built in
`CredentialScheme::prepare_account_for_first_link`:

- The first time a provider identity reaches an existing account, the account
  counts as **proven** if the email-verification capability has marked its
  address verified, or if another provider identity is already linked to it.
  A proven account is left untouched.
- An **unproven** account gets its password replaced with a random one, its
  sessions revoked and its passkeys removed, before the user is logged in.
- A scheme without the email-verification capability has proven nothing, so
  every password account is unproven on its first provider login. A genuine
  user in that position sets a new password through password reset.
- Later logins with an already-linked identity change nothing.

To keep this safe under partial failure, `OAuthFlow::complete` now only
verifies and returns a `VerifiedIdentity`; the scheme secures the account and
calls `OAuthFlow::link` last. `OAuthIdentityStore` gained
`has_identity_for_email`, which the Phase 3 Postgres store must implement (an
index on the email column).

Proof belongs to an account, not to an address, so account deletion also
clears the verified mark and pending verification tokens
(`EmailVerificationTokenStore::forget_email`) and the account's provider links
(`OAuthIdentityStore::unlink_all_for_email`, decided 2026-11-18, reversing the
deferral of 2026-11-17). Without that, a later account reusing the address
would count as proven and already linked.

Securing an unproven account also turns its 2FA requirement off
(`UserStore::set_requires_2fa`), but only when the scheme offers email
verification and the address is unverified (decided 2026-11-19): the setting
was then chosen by someone who never confirmed the address. Without email
verification the scheme cannot tell a squatter from a genuine user, so 2FA
stays and the OAuth login is challenged. A proven account always keeps its 2FA.

**Revoke-all is exact to the token, not to the second** (decided 2026-11-18).
`revoke_all_for_user` sets the cutoff one second past the latest stamp a token
can carry, and `issue` stamps new tokens no earlier than the cutoff; expiry is
always measured from the real clock. A token issued earlier in the same second
as a password change, deletion or first-link cleanup is now rejected.

**A login is pinned to the moment it began** (decided 2026-11-19).
`TokenStrategy` is now `begin(email) -> Ticket` then `issue(email, ticket)`,
and every login path takes its ticket before checking the credential it rests
on (password, 2FA code, elevation, provider link; a passkey login takes it as
soon as the credential names the owner and then confirms the credential
again). If `revoke_all_for_user` runs in between, the login yields nothing
usable:
- JWT: the ticket is the token's issued-at stamp, so the moved cutoff rejects
  it on validation.
- Sessions: the ticket is the user's `SessionStore::revocation_count`;
  `delete_all_for_user` must advance it before deleting, and `issue` discards
  the new session if it changed (`SessionError::Superseded`).

**A per-user credential lock** (built 2026-11-20, closing the last gap of
this section). Securing an unproven account removes several credentials in
sequence, and they could mint one another in between (a session enrols a
passkey, a passkey logs in to a session). Now:
- `TokenStrategy::lock_user` / `unlock_user` take and release a per-user lock
  with a 10 s expiry (`USER_LOCK_TTL_SECONDS`), so a crashed holder cannot
  lock the user out. JWT keeps it in the `TokenEpochStore`, sessions in the
  `SessionStore`; Redis uses `SET NX EX` and a compare-and-delete script.
- Securing an unproven account, account deletion and finishing a passkey
  enrolment all run under it; `begin` refuses a login while it is held
  (409, "try again in a moment"). The scheme waits up to ~1 s for a held lock.
- Removing a user's passkeys also drops their unfinished enrolments
  (`ChallengeStore::delete_all_for_user`), so an enrolment started from a
  session that is then revoked finds no ceremony under the lock.
- The old ordering and the second passkey pass stay, for a lock that expires
  under a store stalled for more than 10 s.

Closed alongside (2026-11-19): every credential reset and account deletion
cancels a half-finished 2FA login for the user (first factor accepted, code
not yet entered), and account deletion revokes a second time after the account
is gone, so a password login that began while it still existed is voided.

Ports the Phase 3 stores must implement because of this section:
`OAuthIdentityStore::{has_identity_for_email, unlink_all_for_email}` (Postgres,
index on email), `EmailVerificationTokenStore::forget_email` (Redis) and
`SessionStore::revocation_count` (Redis: `INCR` before deleting),
`SessionStore::{try_lock_user, unlock_user, is_user_locked}` (Redis: as in
`RedisTokenEpochStore`) and `ChallengeStore::delete_all_for_user` (Redis: keep
a per-user set of ceremony ids, or scan).

Options that were considered and not taken: refuse OAuth login to a
never-linked account (needs a "link a provider while logged in" route that
does not exist yet); keep as is and document the risk.

## Verified route tier (raised 2026-11-19, built 2026-11-20)

The user asked for nested tiers: login → verified → elevated. Built:
- `Routers::verified_router` sits inside the login bucket; with email
  verification, `require_verified_email` (403 if unverified) runs after the
  login middleware and looks the address up per request. Without email
  verification the bucket is plain login routes.
- `AuthService::verified_router(..)` exists only for schemes with email
  verification.
- Library routes in the verified tier: password change (login level), passkey
  enrolment (login level), `/elevate`. Account deletion, logout,
  `/verify-token`, the new `POST /verify-email/resend` and `/verify-email`
  are in the login tier.
- Signup sends the verification link (a failed send is logged; the account
  exists and the user can resend). Resending to a verified address sends
  nothing.
- A provider login marks the address verified, under the credential lock so a
  concurrent deletion cannot leave the mark behind.

**Verifying needs a login** (raised by an automated security review,
decided 2026-11-20). With signup mailing the link, an attacker who signs up
with the victim's address gets the link delivered to the victim; a public
`/verify-email` let the victim's click prove the attacker's account, whose
password then survived the victim's first provider login. Now
`RequiresEmailVerification::verify_email(email, token)` takes the logged-in
user's address and rejects (and burns) a token sent to any other address, and
`/verify-email` is login-gated. A frontend that opens the link without a
session sends the user to log in first. This is what GitHub does.

## Decisions (settled 2026-11-16)

1. **History rewrite (0.4)** — no. Rotate the secrets instead.
2. **Redis/Postgres split (Phase 3 table)** — yes, as tabled.
3. **`passkeys-webauthn` (4.2)** — default-off.
