//! Standalone Axum example crate: OAuth2 / OIDC login, with a browser frontend
//! (see `assets/index.html`).
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
//! `OAuthFlow` yields a verified `Email` — it does not issue a token. This demo
//! then sets a (deliberately simple, plaintext) `demo_session` cookie to show
//! the logged-in state; a real app would issue a JWT/session via its primary
//! scheme here.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
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
use tempered::core::IntoStatusMessage;
use tower_http::services::ServeDir;

type Flow = OAuthFlow<HashMapOAuthStateStore, HashMapOAuthIdentityStore, ReqwestOAuthHttpClient>;

const BASE: &str = "http://localhost:3000";
const ASSETS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/assets");
const STATE_COOKIE: &str = "oauth_state";
const SESSION_COOKIE: &str = "demo_session";

#[derive(Clone)]
struct AppState {
    flow: Arc<Flow>,
}

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

    let state = AppState {
        flow: Arc::new(flow),
    };

    let app = Router::new()
        .route("/login/{provider}", get(login))
        .route("/auth/{provider}/callback", get(callback))
        .route("/me", get(me))
        .route("/logout", get(logout))
        // ---- embedded mock provider ----
        .route("/mock/authorize", get(mock_authorize))
        .route("/mock/token", post(mock_token))
        .route("/mock/userinfo", get(mock_userinfo))
        .with_state(state)
        .fallback_service(ServeDir::new(ASSETS));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("listening on {BASE}");
    axum::serve(listener, app).await.unwrap();
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
            let jar = jar
                .remove(Cookie::build((STATE_COOKIE, "")).path("/").build())
                .add(
                    Cookie::build((SESSION_COOKIE, email.as_ref().expose_secret().clone()))
                        .http_only(true)
                        .same_site(SameSite::Lax)
                        .path("/")
                        .build(),
                );
            (jar, Redirect::to("/")).into_response()
        }
        Err(e) => {
            let (status, message) = e.into_status_message();
            (status, message).into_response()
        }
    }
}

/// Report the currently logged-in user (from the demo session cookie).
async fn me(jar: CookieJar) -> Response {
    match jar.get(SESSION_COOKIE) {
        Some(c) => Json(json!({ "email": c.value() })).into_response(),
        None => (StatusCode::UNAUTHORIZED, Json(json!({ "error": "not logged in" }))).into_response(),
    }
}

async fn logout(jar: CookieJar) -> Response {
    let jar = jar.remove(Cookie::build((SESSION_COOKIE, "")).path("/").build());
    (jar, Redirect::to("/")).into_response()
}

// ---- Mock provider endpoints (a stand-in identity provider) ---------------

#[derive(Deserialize)]
struct AuthorizeParams {
    redirect_uri: String,
    state: String,
}

async fn mock_authorize(Query(p): Query<AuthorizeParams>) -> Redirect {
    // A real provider shows a consent screen; the mock immediately approves.
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
