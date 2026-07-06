# Review Correction Plan

Tracks the fixes from the 2026-07 four-lens review (architecture, credential
security, HTTP security, DX). Phases 1–3 are done; Phase 4 is pending, gated
on the multi-framework goal.

Convention: one well-described commit per task/subtask.

---

## Phase 1 — Documentation ✅ DONE

Commits `b72f1a7..cee9ee0` on `feat/additional-auth-schemes`:

- Rewrote `README.md` as a library quickstart (was the bootcamp two-service readme).
- Fixed the `src/lib.rs` facade doc block (crate name, install snippet, structure).
- Rewrote `ARCHITECTURE.md` to the real 3-crate design + a "Known limitations" section.
- Deleted stale `REFACTORING_STATUS.md`.
- Fixed example doc-comments referencing removed `.with_oauth()` / `.with_passkeys()`;
  documented the `validated_router` + `Extension<Claims>` pattern for protected routes.
- Marked in-memory stores dev-only; clarified that `PostgresUserStore::new` does **not**
  auto-run migrations; removed the empty `examples/migrations/`.

---

## Phase 2 — Security quick wins ✅ DONE

7 commits on `feat/additional-auth-schemes`; whole workspace compiles, 56 adapter
unit tests pass:

- Redacted reset/verification tokens from `#[tracing::instrument]` `skip(...)`.
- Unified login errors to `"Invalid email or password"` (no content oracle) **and**
  added a dummy Argon2 verify on the `PostgresUserStore` not-found path (no timing oracle).
- Raised Argon2 `m_cost` 15000 → 19456 (OWASP floor) via shared constants.
- Generic client error responses; internals logged server-side; `MissingToken` → 401.
- Auth cookie + OAuth-state cookie `Max-Age` (added `time` as a direct dep).
- Example hardening: closed the mock OAuth open redirect; env-based secrets with a
  clearly-labelled dev fallback.

---

## Phase 3 — Larger security & structural ✅ DONE

Implemented 2026-07-06 (commits `ba325e5..1c9955d` on
`feat/additional-auth-schemes`), in the order 3.3 → 3.4 → 3.1 → 3.2 → 3.5 →
3.6. Notable deviations from the plan as written:

- A shared `constant_time_eq` was promoted to `tempered_core` (the OAuth flow
  and API-key scheme carried duplicate private copies); `TwoFaCode` now
  implements constant-time `PartialEq` itself so every store inherits it.
- The epoch store is held as `Arc<dyn TokenEpochStore>` inside `JwtTokens`
  (still a **required** constructor param) rather than a new generic
  parameter — no ripple through the scheme aliases; precedent is
  `validate_auth_token` already taking `&dyn BannedTokenStore`.
- `supports_elevation` shares the primary strategy's epoch store, so
  revoke-all kills elevated tokens too.
- `complete_password_reset` also calls `revoke_all_for_user` (a reset is a
  password change, typically *because* of suspected compromise).
- 3.6: passkeys needed no feature gate (the WebAuthn verifier is a port with
  no heavy dep). Features: `postgres`, `redis`, `oauth-client`,
  `postmark-email`, all default-on; `tempered = { default-features = false }`
  drops sqlx/redis/reqwest from the tree entirely.
- The axum API tests, not run during Phase 2, still asserted pre-Phase-2
  error semantics; aligned in `a5bb12b`.

These changed trait signatures / added ports and needed test updates, each as
its own commit with the affected impls updated in the same commit.

### 3.1 — 2FA attempt-limiting + code expiry → `TwoFaCodeStore`

**Problem:** a 6-digit code (~10⁶) has no attempt cap; the in-memory store has no TTL.
Both stores can be brute-forced within the code's lifetime.

**Trait changes** (`src/tempered_core/src/ports/repositories.rs`):

- `TwoFaCodeStoreError` (line 74): add `TooManyAttempts` (and optionally `CodeExpired`).
- `TwoFaCodeStore` (line 344): keep `validate(...)`'s signature; enforce the attempt
  cap **inside** `validate` and return `TooManyAttempts` past the threshold, deleting
  the code. Max-attempts and TTL are **constructor params** on the impls, not trait
  surface. (Alternative: add an explicit `record_failed_attempt(...) -> Result<u32, _>`;
  rejected as more surface for no gain.)

**Impls to update** (both must change internally):
- `HashMapTwoFaCodeStore` — add a per-`(email, attempt_id)` counter map + a stored
  `Instant` for TTL eviction.
- `RedisTwoFaCodeStore` — atomic `INCR` on an attempts key with matching `EXPIRE`.

**Also (no trait change):** make the code comparison constant-time — reuse the existing
`constant_time_eq` used by the API-key and OAuth-state paths (see 3.4).

**Commit:** `feat(security): attempt-limit and expire 2FA codes`.

---

### 3.2 — Revoke all sessions on password change / account deletion

**Problem:** `change_password` / `delete_account` only mutate the user store, so a
stolen token stays valid for its full TTL after the victim changes their password,
and a deleted user's token keeps working against a signature-only validator.

**Design decision:** revocation belongs with issuance, not in a new capability trait.
`TokenStrategy` already pairs `issue` (create) with `revoke` (one token)
(`token_strategy.rs:36,39`), and `SessionStore` already pairs `create_session` with
`delete_all_for_user` (`repositories.rs:327,340`). So we add **one required method**
to `TokenStrategy` — no default impl, no opt-in trait. Global revocation is
correctness-critical, so every strategy must answer for it explicitly; a third-party
strategy that can't support it must write (and document) its own no-op, visibly
against the stated contract below.

**Trait change** (`src/tempered_adapters/src/authentication/token_strategy.rs:27`):

```rust
/// Invalidate every token/session for a user (e.g. after a password change).
///
/// Contract: after this returns `Ok`, tokens issued to this user *before*
/// the call MUST fail validation.
async fn revoke_all_for_user(&self, email: &Email) -> Result<(), Self::Error>;
```

**Wiring:** `CredentialScheme::change_password` and `::delete_account`
(`credential_scheme.rs`, ~659 / ~682) already hold `self.tokens`, so they call
`self.tokens.revoke_all_for_user(&email)` after mutating the user store. No middleware
plumbing and no need to thread the raw token through the route — invalidating all of a
user's sessions covers the caller's own session and every other device at once.

**Session strategy impl:** one line via `SessionStore::delete_all_for_user`.

**JWT strategy impl — the token-epoch mechanism (option 1, chosen):**

`JwtTokens::revoke` bans a specific token *string* (`token_strategy.rs:124`); there is
no registry of a user's outstanding JWTs, so global revocation needs a per-user cutoff
that validation consults. Implementation:

1. **New port trait** in `tempered_core` (`ports/repositories.rs`):
   ```rust
   #[derive(Debug, Error)]
   pub enum TokenEpochStoreError { /* NotFound?, UnexpectedError(String) */ }

   #[async_trait]
   pub trait TokenEpochStore: Send + Sync {
       /// Earliest `iat` still considered valid for this user; `None` = no cutoff.
       async fn min_valid_iat(&self, email: &Email) -> Result<Option<i64>, TokenEpochStoreError>;
       /// Invalidate every token issued strictly before `cutoff` (usually "now").
       async fn revoke_before(&self, email: &Email, cutoff: i64) -> Result<(), TokenEpochStoreError>;
   }
   ```
   In-memory + Redis impls (Redis: a `token_epoch:{email}` key). **Redis key TTL must
   be ≥ the max token TTL, never shorter** — if the epoch key expires while a deleted
   user's token is still within its `exp`, that token becomes valid again.

2. **The epoch store is a required constructor parameter** on `JwtTokens` /
   `JwtScheme::new`, exactly like the existing `BannedTokenStore` — *not* a typestate
   slot. Slots gate optional product features (2FA, elevation, OAuth); stores the
   strategy needs for correctness (ban list, epoch) are constructor params. Dev setup
   stays one line (`HashMapTokenEpochStore::new()`); production wires the Redis impl.

3. **Add `iat` to `Claims`** (`local_jwt_validator.rs`) — currently only `sub` + `exp`.
   Populate it at issue time in `generate_auth_token`.

4. **Validator check** (`LocalJwtValidator`, `local_jwt_validator.rs:~183`): after the
   signature/`exp`/ban checks, if `min_valid_iat(email)` is `Some(t)` and
   `claims.iat < t`, reject with `InvalidToken`. Two deliberate edge decisions:
   - **Strict `<`, not `<=`:** a token issued in the same second as the revocation
     (e.g. the re-login right after a password change) stays valid. The alternative
     locks users out of their own fresh session; the cost is a ≤1 s replay window.
     Don't "fix" this comparison.
   - **Fail closed:** if the epoch-store read errors, reject the request and log at
     `error!`. A store outage must not silently disable revocation.

5. **`JwtTokens::revoke_all_for_user`** calls `epoch.revoke_before(email, now)`.

**Statefulness note:** this adds one store read per validated request — but the JWT
path is *already* stateful: the validator hits the `BannedTokenStore` on every
validation (that's how logout works). The epoch read is the same shape of lookup, not
an architectural change, which is why it isn't worth an opt-out.

**Commits** (ordered so each compiles — a required trait method breaks all impls at
once, so the JWT plumbing lands before the trait change):
1. `feat(core): add TokenEpochStore port + in-memory/redis impls`
2. `feat(adapters): wire token epoch into JwtTokens (iat claim + validator cutoff)`
   — constructor param, `iat` in `Claims`, validator check, examples updated
3. `feat(adapters): require TokenStrategy::revoke_all_for_user`
   — trait method + both impls (session: `delete_all_for_user`; JWT: `revoke_before`)
4. `fix(security): revoke all sessions on password change and account deletion`

---

### 3.3 — `/elevate` ownership check (no trait change)

**Problem:** `elevate` re-authenticates the body's `email`+`password` but never checks
it matches the current session's subject, so a logged-in user who learns another user's
password gets an elevated token scoped to that other user.

**Fix:** `/elevate` is already in the login-validated bucket (`wiring.rs:218`), so
`Claims` are present. Add `Extension<Claims>` to `routes/elevate.rs` and reject unless
`claims.sub` matches `request.email` before calling `handle_elevate`. Note `claims.sub`
is `Secret`-wrapped and the body email is attacker-supplied — compare with
`constant_time_eq` (as in 3.4), not `==`.

**Commit:** `fix(security): bind elevation to the session owner`.

---

### 3.4 — Robustness fixes

- **Ban-list matches the presented token**, not re-signed claims
  (`local_jwt_validator.rs:~186`). Do this alongside adding `iat` in 3.2 (the re-encode
  currently relies on a deterministic claims round-trip). No trait change.
- **Constant-time 2FA comparison** — reuse `constant_time_eq` in both stores (see 3.1).
- **`aud` / `iss` binding** — add fields to `JwtAuthConfig` and the `Claims` **struct**,
  populate at issue, and configure `Validation` (replace `Validation::default()`).
  `Claims` is a struct, not a trait — additive.
- **Atomic single-use reset (optional trait change):** add
  `consume_token(&self, token) -> Result<Email, PasswordResetTokenStoreError>` to
  `PasswordResetTokenStore` (`repositories.rs:110`), mirroring
  `EmailVerificationTokenStore::consume_token`; `complete_password_reset` uses it
  instead of get+delete. Otherwise, at minimum propagate the `delete_token` error
  instead of `let _ =`.

**Commits:** grouped by area (ban-list, constant-time, aud/iss, reset atomicity).

---

### 3.5 — Re-export the axum layer from the facade (no trait change)

Add `tempered_axum` re-exports to `src/lib.rs` (`auth_service`, `AuthService`,
`middleware::validate_token`, `Claims`, `ApiKeyClaims`) so consumers need one
dependency and one `use`. Update the Phase-1 doc note that said it wasn't re-exported.

**Commit:** `feat(facade): re-export axum service layer`.

---

### 3.6 — Cargo feature flags (no trait change)

Gate `postgres`, `redis`, `oauth`, `passkey` backends behind cargo features so an
in-memory JWT consumer doesn't compile sqlx/redis/reqwest. Mark the heavy deps
`optional = true` and wire feature gates in `tempered_adapters` (and re-expose through
the facade).

**Commit:** `feat(build): gate heavy backends behind cargo features`.

---

## Phase 4 — Deep architecture (PENDING, pre-1.0)

Only worth doing if the "second framework" goal is being pursued soon.

- **Lift the `http` crate out of `tempered_core`:** move `IntoStatusMessage`
  (`http_error.rs:60`) and the `Http*` scheme traits into an adapter/HTTP crate;
  replace `IntoStatusMessage` with a protocol-neutral error-category enum that adapters
  map to status codes. Removes `serde`/`serde_json` from core too.
- **Remove library panics:** unconditional `panic!` in `composable.rs:532` (2FA path);
  `expect` in `handlers/login.rs:47`. Thread errors through return types instead.
  *Scope note (found during Phase 3):* the login `expect` is one of **nine**
  identical `ResponseBuilderError` expects across five handler files
  (login, logout, oauth, passkey, verify_2fa) — the real fix is one shared
  `HandlerError<E> { Auth(E), Response(ResponseBuilderError) }` enum
  (implementing `IntoStatusMessage`) threaded through all handler signatures
  and their routes, not a per-site patch.
- **Decompose `WireCore`** (`wiring.rs:62`) into per-capability traits with no-op
  defaults so `ApiKeyScheme` (which lacks `SupportsRegistration/PasswordChange/
  AccountDeletion`) can use `auth_service()` auto-wiring.
- **Drop axum deps from `tempered_adapters`** (`Cargo.toml:12`) once `cargo udeps`
  confirms they're unused, or split axum-touching code into `tempered_axum`.
- Optionally retire the legacy `composable.rs` prototype from `tempered_core`.

---

## Sequencing

Phase 3 order (as executed): **3.3** (isolated, no trait change) →
**3.4** (ban-list, constant-time, aud/iss, atomic reset) → **3.1**
(`TwoFaCodeStore`) → **3.2** (the multi-commit epoch work) → **3.5/3.6**
(facade/build). Phase 4 is a separate track gated on the multi-framework goal.
