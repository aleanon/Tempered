# Follow-up Plan

Fixes for the findings of the 2026-11-16 codebase analysis. Baseline at the time
of writing: `feat/additional-auth-schemes` @ `398754b`, 128 tests passing, about
40 clippy warnings, branch not pushed.

Convention: one well-described commit per task/subtask.

Order: Phase 0 first (it is a live exposure), then 1 → 2 → push + PR to `main`.
Phases 3–5 are feature work and go in as separate PRs afterwards, so the 56
commits already on this branch are not held behind them.

---

## Phase 0 — Leaked secrets (urgent)

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

## Phase 1 — Stale docs and housekeeping

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

## Phase 2 — Lint and CI

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

- **4.1 Port check first (design risk).** The port takes a challenge generated
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

## Decisions (settled 2026-11-16)

1. **History rewrite (0.4)** — no. Rotate the secrets instead.
2. **Redis/Postgres split (Phase 3 table)** — yes, as tabled.
3. **`passkeys-webauthn` (4.2)** — default-off.
