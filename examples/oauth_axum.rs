//! Axum example: OAuth2 / OIDC login.
//!
//! ```bash
//! cargo run --example oauth_axum
//! ```
//! Then open <http://localhost:3000> and click "Log in".
//!
//! This example is fully self-contained: it embeds a tiny **mock OAuth
//! provider** (the `/mock/*` routes) so it runs offline with no real client
//! credentials. To target a real provider (Google, GitHub, …) instead, point
//! the `OAuthProviderConfig` URLs at the provider and supply a real
//! client id/secret + registered redirect URI.
//!
//! Flow:
//!   GET /login/{provider}  -> OAuthFlow::begin: build authorize URL, bind the
//!                             anti-CSRF `state` to the browser via an HttpOnly
//!                             cookie, 302 to the provider.
//!   GET /auth/{p}/callback -> OAuthFlow::complete: require the cookie `state`
//!                             to match the query `state`, exchange the code,
//!                             fetch userinfo, and return the verified Email.
//!
//! `OAuthFlow` yields a domain `Email` — it does not issue a token. A real app
//! hands that Email to its primary scheme (JWT/session) to start a session;
//! here we simply display it.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use serde::Deserialize;
use serde_json::json;
use tempered::{
    ExposeSecret, HashMapOAuthIdentityStore, HashMapOAuthStateStore, OAuthFlow, OAuthProviderConfig,
    ReqwestOAuthHttpClient, Secret,
};
use tempered_core::IntoStatusMessage;

type Flow = OAuthFlow<HashMapOAuthStateStore, HashMapOAuthIdentityStore, ReqwestOAuthHttpClient>;

const BASE: &str = "http://localhost:3000";
const STATE_COOKIE: &str = "oauth_state";

#[derive(Clone)]
struct AppState {
    flow: Arc<Flow>,
}

#[tokio::main]
async fn main() {
    // The provider URLs point back at this same server's mock endpoints, so the
    // whole round-trip works locally with no external service.
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

    let state = AppState {
        flow: Arc::new(flow),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/login/{provider}", get(login))
        .route("/auth/{provider}/callback", get(callback))
        // ---- embedded mock provider (stands in for Google/GitHub) ----
        .route("/mock/authorize", get(mock_authorize))
        .route("/mock/token", post(mock_token))
        .route("/mock/userinfo", get(mock_userinfo))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("listening on {BASE}  — open it and click 'Log in'");
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> Html<&'static str> {
    Html(r#"<h1>OAuth example</h1><p><a href="/login/mock">Log in with the mock provider</a></p>"#)
}

/// Step 1: begin the flow and bind `state` to this browser via a cookie.
async fn login(
    State(app): State<AppState>,
    Path(provider): Path<String>,
    jar: CookieJar,
) -> Response {
    match app.flow.begin(&provider).await {
        Ok(req) => {
            let cookie = Cookie::build((STATE_COOKIE, req.state))
                .http_only(true)
                .same_site(SameSite::Lax)
                .path("/")
                .build();
            (jar.add(cookie), Redirect::to(&req.authorize_url)).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct CallbackParams {
    code: String,
    state: String,
}

/// Step 2: complete the flow; the cookie `state` must match the query `state`.
async fn callback(
    State(app): State<AppState>,
    Path(provider): Path<String>,
    Query(params): Query<CallbackParams>,
    jar: CookieJar,
) -> Response {
    let cookie_state = jar
        .get(STATE_COOKIE)
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    match app
        .flow
        .complete(&provider, &params.code, &params.state, &cookie_state)
        .await
    {
        Ok(email) => {
            // One-time state cookie is no longer needed; a real app would set a
            // session/JWT cookie here instead.
            let cleared = jar.remove(Cookie::build((STATE_COOKIE, "")).path("/").build());
            let body = Html(format!(
                "<h1>Logged in</h1><p>Verified email: <b>{}</b></p>",
                email.as_ref().expose_secret()
            ));
            (cleared, body).into_response()
        }
        Err(e) => {
            let (status, message) = e.into_status_message();
            (status, message).into_response()
        }
    }
}

// ---- Mock provider endpoints (a stand-in identity provider) ---------------

#[derive(Deserialize)]
struct AuthorizeParams {
    redirect_uri: String,
    state: String,
}

/// A real provider shows a consent screen; the mock immediately "approves" and
/// redirects back with an authorization code.
async fn mock_authorize(Query(p): Query<AuthorizeParams>) -> Redirect {
    Redirect::to(&format!(
        "{}?code=demo-auth-code&state={}",
        p.redirect_uri, p.state
    ))
}

async fn mock_token() -> Json<serde_json::Value> {
    Json(json!({
        "access_token": "demo-access-token",
        "token_type": "bearer",
        "expires_in": 3600
    }))
}

async fn mock_userinfo() -> Json<serde_json::Value> {
    // `email_verified: true` is required — the flow rejects unverified emails.
    Json(json!({
        "sub": "mock-user-123",
        "email": "demo@example.com",
        "email_verified": true
    }))
}
