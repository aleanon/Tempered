//! Standalone Axum example crate: OAuth2 / OIDC login folded into `JwtScheme`
//! as a capability, with a browser frontend (see `assets/index.html`).
//!
//! ```bash
//! cargo run -p tempered-example-oauth
//! # open http://localhost:3000
//! ```
//!
//! Fully self-contained: it embeds a tiny **mock OAuth provider** (`/mock/*`)
//! so it runs offline with no real credentials. To target a real provider
//! (Google, GitHub, …), repoint the `OAuthProviderConfig` URLs and supply real
//! client credentials + a registered redirect URI.
//!
//! The flow uses **PKCE** (S256) on every request, and the mock provider
//! enforces it the way a real one does: it remembers the `code_challenge` sent
//! to `/mock/authorize` and only redeems the code at `/mock/token` when the
//! presented `code_verifier` hashes to it.
//!
//! An OAuth login follows the same rules as a password login: the first login
//! for an email creates the local account (here: `demo@example.com` in the
//! in-memory user store), later ones log in to it, and an account that requires
//! 2FA would still be asked for its code.
//!
//! Unlike the low-level `OAuthFlow` (which only yields a verified `Email`), here
//! the flow is attached to a `JwtScheme` via `.supports_oauth(flow)`, so a
//! successful provider callback issues the scheme's **primary JWT** — the exact
//! same session cookie a password login would produce. The start + callback
//! routes **auto-wire** from `.supports_oauth(flow)`; `auth_service(...).oauth(..)`
//! only overrides their paths. `/me` below reads the issued JWT to prove the
//! session is real.
//!
//! Note: `/me` validates the token *manually* (via `scheme.validator()`) purely
//! to demonstrate the session is real — that's why this example names the fully
//! applied `Scheme` type. To add a normal protected route you don't need any of
//! that: hand a router to `auth_service(...).validated_router(...)` and read the
//! identity with `Extension<Claims>` (see the `jwt_standalone` example).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;
use tempered::core::{AuthValidator, AuthenticationScheme};
use tempered::{
    ExposeSecret, HashMapOAuthIdentityStore, HashMapOAuthStateStore, HashMapTokenEpochStore,
    HashMapUserStore, HashSetBannedTokenStore, JwtAuthConfig, JwtScheme, OAuth, OAuthFlow,
    OAuthProviderConfig, ReqwestOAuthHttpClient, Secret, auth_service, pkce_challenge_s256,
};

/// The fully-applied scheme type: a JWT core with only the OAuth slot enabled.
type Scheme = JwtScheme<
    HashMapUserStore,
    HashSetBannedTokenStore,
    (),
    (),
    (),
    (),
    OAuth<HashMapOAuthStateStore, HashMapOAuthIdentityStore, ReqwestOAuthHttpClient>,
>;

const BASE: &str = "http://localhost:3000";
const ASSETS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/assets");

#[tokio::main]
async fn main() {
    // Provider URLs point back at this server's own mock endpoints.
    let provider = OAuthProviderConfig {
        name: "mock".to_string(),
        client_id: "demo-client".to_string(),
        client_secret: Secret::new("demo-secret".to_string()),
        auth_url: format!("{BASE}/mock/authorize"),
        token_url: format!("{BASE}/mock/token"),
        userinfo_url: format!("{BASE}/mock/userinfo"),
        redirect_uri: format!("{BASE}/auth/mock/callback"),
        scopes: vec!["openid".to_string(), "email".to_string()],
    };

    let flow = OAuthFlow::new(
        HashMapOAuthStateStore::new(),
        HashMapOAuthIdentityStore::new(),
        ReqwestOAuthHttpClient::new(),
    )
    .with_provider(provider);

    let jwt_config = JwtAuthConfig {
        jwt_cookie_name: "jwt".to_string(),
        // Demo only: read from the environment, falling back to a clearly-labelled
        // insecure value. Production must supply a strong random JWT_SECRET.
        jwt_secret: Secret::new(
            std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "dev-only-insecure-change-me-0123456789abcd".to_string()),
        ),
        token_ttl_in_seconds: 3600,
        audience: None,
        issuer: None,
    };

    // The OAuth flow is the only capability this scheme opts into.
    let scheme: Scheme = JwtScheme::new(
        HashMapUserStore::new(),
        jwt_config,
        HashSetBannedTokenStore::new(),
        HashMapTokenEpochStore::new(),
    )
    .supports_oauth(flow);

    // `auth_service` owns the OAuth start/callback routes (and POST `/logout`,
    // which clears the JWT cookie) and serves the frontend from `ASSETS`.
    let auth_router: Router = auth_service(scheme.clone(), ASSETS.to_string())
        // OAuth routes auto-wire from `supports_oauth`; override to this frontend's paths.
        .oauth("/login/{provider}", "/auth/{provider}/callback")
        .into();

    // `/me` (reads the issued JWT) and the embedded mock provider need the scheme
    // as state, so they live in a sibling router merged into the auth service.
    let extra: Router = Router::new()
        .route("/me", get(me))
        .route("/mock/authorize", get(mock_authorize))
        .route("/mock/token", post(mock_token))
        .route("/mock/userinfo", get(mock_userinfo))
        .with_state(scheme);

    let app = auth_router.merge(extra);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("listening on {BASE}");
    axum::serve(listener, app).await.unwrap();
}

/// Report the currently logged-in user by validating the JWT the OAuth callback
/// issued — proving an OAuth login yields a normal, verifiable session.
async fn me(State(scheme): State<Scheme>, headers: HeaderMap) -> Response {
    // The scheme's validator reads the `jwt` cookie from the request headers.
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

// ---- Mock provider endpoints (a stand-in identity provider) ---------------

/// Authorization codes the mock has issued, each mapped to the PKCE
/// `code_challenge` it was issued against. A real provider keeps the same
/// association (plus client id, redirect URI and an expiry).
static ISSUED_CODES: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(Mutex::default);
static NEXT_CODE: AtomicU64 = AtomicU64::new(1);

#[derive(Deserialize)]
struct AuthorizeParams {
    redirect_uri: String,
    state: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

async fn mock_authorize(Query(p): Query<AuthorizeParams>) -> Response {
    // Validate redirect_uri against the one this provider is configured to allow,
    // exactly as a real provider must — otherwise this endpoint is an open
    // redirect (send any `redirect_uri` and it bounces the victim there).
    let expected = format!("{BASE}/auth/mock/callback");
    if p.redirect_uri != expected {
        return (StatusCode::BAD_REQUEST, "Invalid redirect_uri").into_response();
    }
    // Require PKCE with S256; refuse `plain` and requests without a challenge.
    let (Some(challenge), Some("S256")) = (p.code_challenge, p.code_challenge_method.as_deref())
    else {
        return (StatusCode::BAD_REQUEST, "PKCE with S256 is required").into_response();
    };

    // A real provider shows a consent screen; the mock immediately approves and
    // binds the code it hands out to the challenge it was given.
    let code = format!(
        "demo-auth-code-{}",
        NEXT_CODE.fetch_add(1, Ordering::Relaxed)
    );
    ISSUED_CODES.lock().unwrap().insert(code.clone(), challenge);

    Redirect::to(&format!(
        "{}?code={}&state={}",
        p.redirect_uri, code, p.state
    ))
    .into_response()
}

#[derive(Deserialize)]
struct TokenParams {
    code: String,
    code_verifier: Option<String>,
}

async fn mock_token(Form(p): Form<TokenParams>) -> Response {
    // Codes are single-use: remove it whether or not the verifier checks out.
    let challenge = ISSUED_CODES.lock().unwrap().remove(&p.code);
    let verified = match (challenge, p.code_verifier) {
        (Some(challenge), Some(verifier)) => pkce_challenge_s256(&verifier) == challenge,
        _ => false,
    };
    if !verified {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_grant" })),
        )
            .into_response();
    }

    Json(json!({
        "access_token": "demo-access-token",
        "token_type": "bearer",
        "expires_in": 3600
    }))
    .into_response()
}

async fn mock_userinfo() -> Json<serde_json::Value> {
    // `email_verified: true` is required — the flow rejects unverified emails.
    Json(json!({
        "sub": "mock-user-123",
        "email": "demo@example.com",
        "email_verified": true
    }))
}
