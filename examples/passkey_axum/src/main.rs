//! Standalone Axum example crate: passkey (WebAuthn) login folded into
//! `JwtScheme` as a capability, with a browser frontend (see `assets/index.html`).
//!
//! ```bash
//! cargo run -p tempered-example-passkey                     # simulated authenticator
//! cargo run -p tempered-example-passkey --features webauthn # real passkeys
//! # open http://localhost:3000
//! ```
//!
//! Two modes, one server wiring (`JwtScheme::new(...).supports_passkeys(flow)`):
//!
//! - **Simulated** (default, offline): a deliberately trivial `DemoVerifier` (`src/demo.rs`)
//!   stands in for a real `WebAuthnVerifier`, and the frontend *simulates*
//!   the authenticator. Deterministic, no hardware needed.
//! - **Real** (`--features webauthn`): the production `WebAuthnRsVerifier`,
//!   and the page calls `navigator.credentials.create/get`, so your
//!   browser's passkey manager, a phone or a security key answers. Open it
//!   at `http://localhost:3000` exactly: the relying party is `localhost`,
//!   and browsers allow WebAuthn over plain HTTP only there.
//!
//! The page tells the modes apart by the options the server returns: real
//! ones are `{ publicKey: … }`. The passkey ceremony routes
//! **auto-wire** from that `supports_passkeys` call — there is no route opt-in to
//! add (pass a path to `auth_service(...).passkeys(..)` only to override the
//! prefix).
//!
//! Passkeys are enrolled **for an existing, logged-in account**: the two
//! `register/*` routes sit behind the login middleware and enroll for the
//! session's owner, so the demo first creates an account with a password, logs
//! in, enrolls a passkey, logs out, and then signs back in with the passkey
//! alone. (Enrolling must be authenticated — otherwise anyone could attach their
//! own authenticator to someone else's account.)
//!
//! A successful authentication ceremony issues the scheme's **primary JWT** — the
//! same session cookie a password or OAuth login would produce, which `/me`
//! validates below.
//!
//! Note: like the OAuth example, `/me` validates the JWT manually to prove the
//! session is real, which is why this example names the fully applied `Scheme`
//! type. A normal protected route needs none of that — use
//! `auth_service(...).validated_router(...)` with `Extension<Claims>` (see the
//! `jwt_standalone` example).
//!
//! ⚠️  `DemoVerifier` performs no cryptography and trusts the client-supplied
//! credential id. The real mode shows the production setup: the same
//! `PasskeyFlow` with `WebAuthnRsVerifier`.

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::json;
use tempered::core::{AuthValidator, AuthenticationScheme};
use tempered::{
    ExposeSecret, HashMapChallengeStore, HashMapPasskeyCredentialStore, HashMapTokenEpochStore,
    HashMapUserStore, HashSetBannedTokenStore, JwtAuthConfig, JwtScheme, PasskeyFlow, Passkeys,
    Secret, auth_service,
};

/// The fully-applied scheme type: a JWT core with only the passkey slot enabled
/// (password signup is a runtime flag, not a type-level slot).
type Scheme = JwtScheme<
    HashMapUserStore,
    HashSetBannedTokenStore,
    (),
    (),
    (),
    (),
    (),
    Passkeys<HashMapPasskeyCredentialStore, HashMapChallengeStore, Verifier>,
>;

#[cfg(not(feature = "webauthn"))]
mod demo;

#[cfg(not(feature = "webauthn"))]
type Verifier = demo::DemoVerifier;
#[cfg(feature = "webauthn")]
type Verifier = tempered::WebAuthnRsVerifier;

#[cfg(not(feature = "webauthn"))]
fn verifier() -> Verifier {
    println!("simulated authenticator (run with --features webauthn for real passkeys)");
    demo::DemoVerifier
}

/// The production verifier for `http://localhost:3000`. The user-handle key
/// turns each email into the opaque id stored on the authenticator; load it
/// from the environment in a real app and never change it.
#[cfg(feature = "webauthn")]
fn verifier() -> Verifier {
    println!("real passkeys: open exactly {BASE}");
    let key = std::env::var("PASSKEY_USER_HANDLE_KEY")
        .map(String::into_bytes)
        .unwrap_or_else(|_| b"demo-only-user-handle-key-0123456789".to_vec());
    tempered::WebAuthnRsVerifier::new("localhost", BASE, Secret::new(key))
        .expect("localhost is a valid relying party for http://localhost:3000")
}

const BASE: &str = "http://localhost:3000";
const ASSETS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/assets");

#[tokio::main]
async fn main() {
    let flow = PasskeyFlow::new(
        HashMapPasskeyCredentialStore::new(),
        HashMapChallengeStore::new(),
        verifier(),
    );

    let jwt_config = JwtAuthConfig {
        jwt_cookie_name: "jwt".to_string(),
        jwt_secret: Secret::new("input a long random generated string here".to_string()),
        token_ttl_in_seconds: 3600,
        audience: None,
        issuer: None,
    };

    // Password signup creates the account a passkey is then enrolled for.
    let scheme: Scheme = JwtScheme::new(
        HashMapUserStore::new(),
        jwt_config,
        HashSetBannedTokenStore::new(),
        HashMapTokenEpochStore::new(),
    )
    .supports_registration()
    .supports_passkeys(flow);

    // The four passkey ceremony routes under `/passkey/*` auto-wire from
    // `supports_passkeys`: `register/{start,finish}` behind the login middleware,
    // `login/{start,finish}` public. `/signup`, `/login`, `/logout` and the
    // frontend come for free.
    let auth_router: Router = auth_service(scheme.clone(), ASSETS.to_string()).into();

    // `/me` reads the JWT the login ceremony issued, so it needs the scheme as
    // state and lives in a sibling router merged into the auth service.
    let extra: Router = Router::new().route("/me", get(me)).with_state(scheme);

    let app = auth_router.merge(extra);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("listening on {BASE}");
    axum::serve(listener, app).await.unwrap();
}

/// Report the currently logged-in user by validating the JWT the passkey login
/// issued — proving a passkey login yields a normal, verifiable session.
async fn me(State(scheme): State<Scheme>, headers: HeaderMap) -> Response {
    let (mut parts, _) = axum::http::Request::new(()).into_parts();
    parts.headers = headers;

    match scheme.validator().validate(&parts).await {
        Ok(claims) => Json(json!({ "email": claims.sub.expose_secret() })).into_response(),
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "not logged in" })),
        )
            .into_response(),
    }
}
