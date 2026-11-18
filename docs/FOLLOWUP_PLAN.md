# Follow-up Plan

Fixes for the findings of the 2026-11-16 codebase analysis. Baseline at the time
of writing: `feat/additional-auth-schemes` @ `398754b`, 128 tests passing, about
40 clippy warnings, branch not pushed.

Convention: one well-described commit per task/subtask.

Order: Phase 0 first (it is a live exposure), then 1 → 2 → push + PR to `main`.
Phases 3–5 are feature work and go in as separate PRs afterwards, so the 56
commits already on this branch are not held behind them.

---

## Phase 0 — Leaked secrets (urgent) ✅ repo side DONE — rotation (0.1) still owed

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

## Phase 3 — Production stores for the new schemes

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
(`UserStore::set_requires_2fa`): the setting was chosen by whoever signed up,
and the owner must not be held to a factor they did not set up. A proven
account keeps its 2FA and is still challenged on an OAuth login.

**Revoke-all is exact to the token, not to the second** (decided 2026-11-18).
`revoke_all_for_user` sets the cutoff one second past the latest stamp a token
can carry, and `issue` stamps new tokens no earlier than the cutoff; expiry is
always measured from the real clock. A token issued earlier in the same second
as a password change, deletion or first-link cleanup is now rejected. Accepted
and not closed: a login request that had already passed its credential check
when the cleanup ran and issues its token just after.

Ports the Phase 3 stores must implement because of this section:
`OAuthIdentityStore::{has_identity_for_email, unlink_all_for_email}` (Postgres,
index on email) and `EmailVerificationTokenStore::forget_email` (Redis).

Options that were considered and not taken: refuse OAuth login to a
never-linked account (needs a "link a provider while logged in" route that
does not exist yet); keep as is and document the risk.

## Decisions (settled 2026-11-16)

1. **History rewrite (0.4)** — no. Rotate the secrets instead.
2. **Redis/Postgres split (Phase 3 table)** — yes, as tabled.
3. **`passkeys-webauthn` (4.2)** — default-off.
