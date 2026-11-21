# Design: framework-neutral routes

Status: **built** (2026-11-22, `c47c57b..` on `main`). Decisions taken
(§10): the malformed-JSON body change accepted (statuses 415/400/422 kept,
messages are the library's); both override forms (`.login(..)` and
`.path(RouteId, ..)`); the proof adapter is framework-free
(`tempered_adapters/tests/framework_free.rs`, no hyper needed); 7.1 went first.
As built, steps 1–5 landed as one commit, and the tier-rule tests sit in
`endpoints/table_tests.rs`. Original proposal follows.

Status at writing: **proposal** (2026-11-21). Requested after the
2026-11-21 review, which noted that a second web framework would mean
copying the axum layer. Nothing here changes behaviour; it moves decisions.

## 1. The problem

Today the library decides *which routes exist, at which path, behind which
check* inside `tempered_axum`. Measured at `68c5f78`:

| File(s) | Lines | What it does | Axum-specific? |
|---|---|---|---|
| `tempered_axum/src/wiring.rs` | 581 | Slot → route decisions: which capability mounts what, at which tier. Two impls per slot (`()` / real), 13 `Wire*` impls | The **decisions** are not; the code that carries them is |
| `tempered_axum/src/routes/*` (16 files) | 1,075 | Request parsing (`Json`, `Extension<Claims>`, `Path`, `Query`, cookies), call a handler, map the error to `{"error": ..}` | Mostly glue; the error mapping is written three different ways |
| `tempered_axum/src/route_config.rs` | 106 | Route buckets + `fn`-pointer hooks for the elevated/verified layers and the elevation-aware logout | Yes |
| `tempered_axum/src/middleware.rs` | 155 | Login, elevated and verified checks | The checks are not; the `Next` plumbing is |
| `tempered_axum/src/auth_service.rs` | 243 | Builder, path overrides, assembling buckets, static assets | Yes (stays) |
| `tempered_axum/src/adapters.rs` | 341 | `AuthRequest` / `ResponseBuilder` for axum types | Yes (shrinks) |
| `tempered_adapters/src/handlers/*` | 834 | The framework-agnostic handlers the routes call | No |

A second adapter (actix-web, poem, salvo, ...) would have to copy the first
four rows, about 1,900 lines. Worse, it would re-make every tier decision:
"`/change-password` needs a verified address", "passkey enrolment is never
public", "`/verify-email` needs a login". Those are security rules. Two
copies drift, and a route mounted one tier too low is a vulnerability, not a
bug.

Even with axum alone, the rules are hard to audit: they are spread across a
dozen trait impls, and no test can ask "which routes are public?".

## 2. Goals and non-goals

Goals:
1. Every route decision (id, method, path, tier) is made once, in
   `tempered_adapters`, as data.
2. Library routes are authorized **inside the library**: an adapter mounts a
   route and forwards the request, and cannot put it behind the wrong check.
3. A framework adapter is request/response conversion plus mounting, about
   300 lines, with no per-capability code.
4. Capability gating stays compile-time: a scheme without OAuth has no
   OAuth routes and no OAuth code paths. No new runtime configuration.
5. The public axum API (`auth_service(..)`, `.login("/signin")`,
   `.validated_router(..)`, `Extension<Claims>`) does not change for users.

Non-goals:
- Shipping a second adapter in the same effort (see §9).
- Changing any route's behaviour, path or status codes, except the
  malformed-JSON rejection body (§5.3).
- Making the user's own routes framework-neutral. They are the app's code
  and stay in its framework; the library only provides the tier checks.

## 3. The shape: a route table and one dispatcher

`tempered_adapters` gains a module `endpoints` (no web-framework
dependency; it uses `http`, `bytes`, `serde_json`):

```rust
/// Every route the library can serve. Stable identifiers, used for path
/// overrides and in tests.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RouteId {
    Login, Logout, VerifyToken, Signup,
    ChangePassword, DeleteAccount,
    Verify2Fa,
    Elevate, VerifyElevatedToken,
    PasswordResetInitiate, PasswordResetComplete,
    VerifyEmail, ResendVerification,
    OAuthStart, OAuthCallback,
    PasskeyRegisterStart, PasskeyRegisterFinish,
    PasskeyLoginStart, PasskeyLoginFinish,
}

/// What a request must prove before the route runs. The tiers nest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier { Public, Login, Verified, Elevated }

pub struct RouteSpec {
    pub id: RouteId,
    pub method: http::Method,
    pub path: PathTemplate,   // e.g. "/oauth/{provider}/callback"
    pub tier: Tier,
}

/// A request, already read: head, body bytes, and the path parameters the
/// framework's router matched.
pub struct EndpointRequest {
    pub parts: http::request::Parts,
    pub body: bytes::Bytes,
    pub params: PathParams,   // small map: "provider" -> "google"
}

/// Implemented once per scheme family in tempered_adapters.
#[async_trait]
pub trait Endpoints: Send + Sync {
    /// The routes this scheme serves, with overrides applied. Pure data.
    fn routes(&self, overrides: &PathOverrides) -> Vec<RouteSpec>;

    /// Authorize for `spec.tier`, then run the route. Always answers;
    /// errors are already classified into status + `{"error": ..}`.
    async fn handle(&self, spec: &RouteSpec, req: EndpointRequest)
        -> http::Response<String>;
}
```

`handle` takes the whole `RouteSpec`, not just the id, so the tier it
enforces is the one in the table. An adapter has nothing to get wrong: it
mounts `spec.path` for `spec.method` and calls `handle(spec, request)`.

### 3.1 Keeping capability gating at compile time

`routes()` and `handle()` must agree with the slots, or a route could be
listed that the scheme cannot serve. Both come from one private trait per
capability, in the same pattern as `PasskeyCleanup` and `ElevationRevoke`
(a no-op for `()`, the real thing for the filled slot):

```rust
#[async_trait]
trait OAuthEndpoints<S> {
    fn routes(&self, o: &PathOverrides, out: &mut Vec<RouteSpec>);
    async fn handle(&self, scheme: &S, id: RouteId, req: Authorized)
        -> Option<http::Response<String>>; // None: not this slot's route
}
impl<S> OAuthEndpoints<S> for () { /* no routes, None */ }
impl<S, ST, ID, HC> OAuthEndpoints<S> for OAuth<ST, ID, HC>
where S: HttpOAuth2Scheme, /* the bounds wiring.rs states today */ { .. }
```

`CredentialScheme::routes` concatenates the slots' lists, and `handle` asks
each slot in turn. A slot only lists routes its own `handle` serves, so the
two cannot drift. The trait bounds now spread over the `Wire*` impls move
onto these impls, once, in the crate that owns the slots.

This replaces the `Wire*` traits, `AutoWire`, `ElevatedBucketClaims` and
`Routers`' `fn`-pointer hooks. Those exist only because axum's router type
had to be built under bounds known at the slot. With the decision in
`tempered_adapters`, the hooks have nothing left to do.

`ApiKeyScheme` implements `Endpoints` with no routes (as `AutoWire` does
today).

### 3.2 Authorization inside `handle`

`handle` runs the check for `spec.tier` before the route:

| Tier | Check (code that exists today, moved) |
|---|---|
| `Public` | none |
| `Login` | `scheme.validator().validate(&parts)` (from `middleware::validate_token`) |
| `Verified` | login, then `is_email_verified` if the scheme has email verification (from `require_verified_email`). Without it, the same as `Login`, as now |
| `Elevated` | `elevated_validator().validate(&parts)` (from `validate_elevated_token`) |

The result is the caller's `Email`, which is all a library route needs.
The checks are the slot traits again: `Verified` and `Elevated` are no-ops
or real per slot.

## 4. What the axum crate becomes

```rust
// The whole of library-route mounting, replacing wiring.rs + routes/*.
for spec in scheme.routes(&overrides) {
    let scheme = scheme.clone();
    let spec = Arc::new(spec);
    router = router.route(
        &spec.path.render_axum(),                 // "{provider}" is axum's syntax already
        on(method_filter(&spec.method), move |Path(params), req: Request| async move {
            let req = EndpointRequest::from_axum(req, params).await?;   // reads the body (limit applies)
            Ok::<_, Response>(scheme.handle(&spec, req).await.into_response())
        }),
    );
}
```

What stays in `tempered_axum`:
- The `auth_service` builder and its path-override methods. They now fill
  a `PathOverrides` keyed by `RouteId`, which moves to `tempered_adapters`.
- The three middlewares, for **user** routers only (`validated_router`,
  `verified_router`, `validated_elevated_router`). These still insert typed
  `Extension<Claims>`, because user code reads them. They call the same
  check functions `handle` uses, so the two cannot disagree.
- Static assets (`ServeDir`).
- Request/response conversion (most of `adapters.rs`).

Estimated: wiring.rs, route_config.rs and routes/* (about 1,760 lines)
are removed. About 250 lines of mounting and conversion replace them.
`tempered_adapters::endpoints` gains about 900–1,100 lines, including the
JSON parsing the routes did. The total shrinks, and the per-capability part
exists once.

## 5. Details that need care

### 5.1 Request bodies and CSRF

Today axum's `Json` extractor rejects a body without `Content-Type:
application/json`. That is part of the CSRF defence (a cross-site form
cannot send JSON without a CORS preflight). `handle` must keep it: every
route with a body requires `application/json` (`415` otherwise) before
parsing. A test pins this per route, so no adapter can lose it.

Body size: the framework reads the body, so its limit applies (axum's
default is 2 MB). `EndpointRequest::from_axum` keeps that. The library
documents the expectation for other adapters.

### 5.2 Path templates and overrides

`PathTemplate` holds segments (`Literal("oauth")`, `Param("provider")`, ..)
and renders per framework. `{name}` is axum's and actix's syntax; poem and
salvo use `:name` / `<name>`. Overrides are parsed from the `{name}` form,
which users write today, and must keep the parameters the route needs. A
`/oauth/start` override without `{provider}` is refused at startup.

The table also makes the planned startup check easy: two routes with the
same method and path panic with both `RouteId`s named. Today that is axum's
duplicate-route panic, which names neither.

### 5.3 Errors

The routes map errors in three different ways today (`IntoStatusMessage`,
per-route enums with fixed statuses, plain strings). `handle` uses one
mapping: `ClassifyError` → `ErrorCategory` → status, and the body is always
`{"error": message}`. Validation errors (`UserError`) stay `400` with their
message, as now.

One visible change: a malformed JSON body now answers `400 {"error":
"Malformed request body"}` instead of axum's rejection text. That text came
from axum and differs per framework, so a neutral layer cannot keep it.

### 5.4 Cookies and redirects

Handlers already return `http::Response<String>` with `Set-Cookie` and
`Location` headers, built by `HttpResponseBuilder`. Nothing changes there.
The OAuth callback's state cookie is read from `parts` through the
existing `AuthRequest` impl for `Parts`.

### 5.5 Performance

`handle` matches on `RouteId` and walks the slots (at most seven
`Option` checks) before the route runs, which costs nothing next to a
store round trip. The table is built once at startup. 7.2 (`Arc` the
scheme) applies here unchanged.

## 6. Tests the table makes possible

- **Tier invariants, for every capability combination** (built from the
  in-memory stores, no HTTP):
  - nothing that changes a credential is `Public`;
  - passkey enrolment is never below `Verified`;
  - `/verify-email` is `Login`.

  Today these rules are only checked route by route in the axum tests.
- **Gating:** a scheme without slot X lists none of X's routes.
- **Unique paths** per method, defaults and overrides.
- **Content-Type 415** for every body-taking route.
- The existing axum integration tests (`tests/*.rs`, `tests/api/`) stay as
  the end-to-end proof that behaviour did not change.

## 7. Migration, one commit each

1. `endpoints` module: `RouteId`, `Tier`, `RouteSpec`, `PathTemplate`,
   `PathOverrides` (moved), `EndpointRequest`; plus the tier checks as free
   functions. No behaviour change; the axum middleware calls the moved
   checks.
2. `Endpoints` for `CredentialScheme`: `routes()` via per-slot traits, plus
   tests that it lists exactly what `wiring.rs` mounts today (a temporary
   test comparing the two).
3. `handle` for the core routes (login, logout, verify-token, signup,
   change password, delete account), with the JSON and Content-Type
   handling.
4. `handle` for 2FA, elevation, password reset, email verification.
5. `handle` for OAuth and passkeys.
6. Switch `tempered_axum` to mount the table; delete `wiring.rs`,
   `route_config.rs` and `routes/*`. All integration tests must pass
   unchanged, apart from the malformed-JSON body (§5.3).
7. Tier-invariant and gating tests (§6) over every capability combination.
8. Docs: ARCHITECTURE.md, README ("adding a framework adapter"), CLAUDE.md
   layout.

Steps 1–5 add code next to the old path; step 6 is the switch. Each step
leaves the workspace green.

## 8. Risks

- **Bounds move, not vanish.** The where-clauses on `Wire*` impls reappear
  on the slot endpoint traits. Compile errors for a misconfigured scheme
  then point at `Endpoints` instead of `AutoWire`. Phase 9.1
  (`#[diagnostic::on_unimplemented]`) belongs on these traits.
- **Typed claims for user routes** still need the scheme's `Claims` type,
  so the three middlewares stay generic in the adapter. That is about 100
  lines per framework, and the only per-framework auth code left.
- **The 9th capability** still means a new slot trait with two impls. It
  is one place instead of two (adapters + wiring), but it is not free.
  Phase 9.7 (capability bundle) is independent of this design.

## 9. What a second adapter would then cost

For an `http` 1.x framework (poem, salvo, or anything on hyper 1): about
250–300 lines. It converts the request into `EndpointRequest` and the
response back, mounts the table, and wraps the three user-router
middlewares and static files.

actix-web 4 uses `http` 0.2 types, so its conversion copies method, URI and
headers into `http` 1.x `Parts`. That is cheap, but it is not zero-copy; check
the current actix version when building it. Expect about 350 lines plus
its own integration tests (the axum `tests/` are the template).

Not part of this effort. With the table in place, an adapter is a
self-contained crate (`tempered_actix`) that needs no changes elsewhere.

## 10. Decisions needed before building

1. **Malformed-JSON body**: accept the one visible change in §5.3?
2. **Path overrides**: keep the per-route methods (`.login("/signin")`) as
   the only API, or also expose `.path(RouteId::Login, "/signin")`? The
   methods stay either way. Recommendation: both, since the `RouteId` form
   gives new routes an override with no new method.
3. **Scope**: this design only (steps 1–8), or also a proof adapter? A
   minimal, test-only adapter on plain `hyper`/`tower`, in
   `tempered_adapters` tests, would show the table works without axum at
   about 150 lines. Recommendation: yes. It keeps "framework-neutral" honest
   in CI.
4. **Order against Phase 7.1** (async Redis): independent. 7.1 touches
   stores, this touches delivery. Recommendation: 7.1 first, since it
   fixes a production problem and this does not.
