# Review Correction Plan

Tracks the fixes from the 2026-07 four-lens review (architecture, credential
security, HTTP security, DX). Phases 1–2 are done; Phases 3–4 are pending.

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

## Phase 3 — Larger security & structural (PENDING)

These change trait signatures / add ports and need test updates, so each is its
own commit with the affected impls updated in the same commit.

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
`delete_all_for_user` (`repositories.rs:327,340`). So we add **one method** to
`TokenStrategy`, not a new opt-in trait.

**Trait change** (`src/tempered_adapters/src/authentication/token_strategy.rs:27`):

```rust
/// Invalidate every token/session for a user (e.g. after a password change).
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
       /// Invalidate every token issued at or before `cutoff` (usually "now").
       async fn revoke_before(&self, email: &Email, cutoff: i64) -> Result<(), TokenEpochStoreError>;
   }
   ```
   In-memory + Redis impls (Redis: a `token_epoch:{email}` key).

2. **Add `iat` to `Claims`** (`local_jwt_validator.rs`) — currently only `sub` + `exp`.
   Populate it at issue time in `generate_auth_token`.

3. **Validator check** (`LocalJwtValidator`, `local_jwt_validator.rs:~183`): after the
   signature/`exp`/ban checks, if `min_valid_iat(email)` is `Some(t)` and
   `claims.iat < t`, reject with `InvalidToken`.

4. **`JwtTokens::revoke_all_for_user`** calls `epoch.revoke_before(email, now)`.

**Statefulness tradeoff (call this out):** consulting `min_valid_iat` on validation
means the JWT path is no longer purely stateless — it costs one store read per
protected request when the feature is active. Mitigate by making the epoch store an
**optional generic slot** on `JwtTokens` (consistent with the codebase's typestate
pattern): with the unit type `()` there is no epoch store, `revoke_all_for_user`
returns an explicit "unsupported" error, and the validator does no extra read (fully
stateless, as today); with a real store wired in, global revocation works at the cost
of the per-request lookup. Document the tradeoff where `JwtTokens` is constructed.

**Commits:**
- `feat(adapters): add TokenStrategy::revoke_all_for_user (session impl)`
- `feat(core): add TokenEpochStore port + in-memory/redis impls`
- `feat(security): JWT global revocation via token epoch (iat cutoff)`
- `fix(security): revoke all sessions on password change and account deletion`

---

### 3.3 — `/elevate` ownership check (no trait change)

**Problem:** `elevate` re-authenticates the body's `email`+`password` but never checks
it matches the current session's subject, so a logged-in user who learns another user's
password gets an elevated token scoped to that other user.

**Fix:** `/elevate` is already in the login-validated bucket (`wiring.rs:218`), so
`Claims` are present. Add `Extension<Claims>` to `routes/elevate.rs` and reject if
`claims.sub != request.email` before calling `handle_elevate`.

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
- **Decompose `WireCore`** (`wiring.rs:62`) into per-capability traits with no-op
  defaults so `ApiKeyScheme` (which lacks `SupportsRegistration/PasswordChange/
  AccountDeletion`) can use `auth_service()` auto-wiring.
- **Drop axum deps from `tempered_adapters`** (`Cargo.toml:12`) once `cargo udeps`
  confirms they're unused, or split axum-touching code into `tempered_axum`.
- Optionally retire the legacy `composable.rs` prototype from `tempered_core`.

---

## Sequencing

Phase 3 order: **3.3** (isolated, no trait change) → **3.4 constant-time + aud/iss** →
**3.1** (`TwoFaCodeStore`) → **3.2** (the multi-commit epoch work) → **3.5/3.6**
(build/facade). Phase 4 is a separate track gated on the multi-framework goal.
