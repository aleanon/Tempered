//! Refresh tokens and bearer tokens through the axum service: rotation,
//! reuse revoking the login, logout and password change revoking it, and
//! `Authorization: Bearer`. In-memory stores and `tower::oneshot`.

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    routing::get,
};
use secrecy::{ExposeSecret, Secret};
use serde_json::{Value, json};
use tempered_adapters::auth_validation::local_jwt_validator::{Claims, JwtAuthConfig};
use tempered_adapters::authentication::jwt_scheme::JwtScheme;
use tempered_adapters::authentication::token_strategy::RefreshTokens;
use tempered_adapters::persistence::{
    HashMapRefreshTokenStore, HashMapTokenEpochStore, HashMapUserStore, HashSetBannedTokenStore,
};
use tempered_axum::auth_service::auth_service;
use tower::ServiceExt; // for `oneshot`

const CREDENTIALS: &str =
    r#"{"email":"user@example.com","password":"correct-horse","requires2FA":false}"#;

fn app() -> Router {
    let scheme = JwtScheme::new(
        HashMapUserStore::new(),
        JwtAuthConfig {
            jwt_cookie_name: "jwt".to_string(),
            jwt_secret: Secret::new("a-test-secret-that-is-long-enough".to_string()),
            token_ttl_in_seconds: 300,
            audience: None,
            issuer: None,
        },
        HashSetBannedTokenStore::new(),
        HashMapTokenEpochStore::new(),
    )
    .supports_registration()
    .supports_password_change()
    .supports_refresh_tokens(RefreshTokens::new(HashMapRefreshTokenStore::new(), 3600))
    .tokens_in_body();
    auth_service(scheme, String::new())
        .validated_router(Router::new().route("/whoami", get(whoami)))
        .into()
}

async fn whoami(Extension(claims): Extension<Claims>) -> String {
    claims.sub.expose_secret().clone()
}

struct Reply {
    status: StatusCode,
    cookies: Vec<String>,
    body: Value,
}

impl Reply {
    fn cookie(&self, name: &str) -> String {
        self.cookies
            .iter()
            .find(|c| c.starts_with(&format!("{name}=")))
            .unwrap_or_else(|| panic!("no {name} cookie in {:?}", self.cookies))
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }
}

async fn send(app: &Router, request: Request<Body>) -> Reply {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|c| c.to_str().unwrap().to_string())
        .collect();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    Reply {
        status,
        cookies,
        body: serde_json::from_slice(&body).unwrap_or(Value::Null),
    }
}

fn post(path: &str, cookie: Option<&str>, body: &str) -> Request<Body> {
    let mut request = Request::post(path).header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    request.body(Body::from(body.to_string())).unwrap()
}

async fn logged_in(app: &Router) -> Reply {
    assert!(
        send(app, post("/signup", None, CREDENTIALS))
            .await
            .status
            .is_success()
    );
    let reply = send(app, post("/login", None, CREDENTIALS)).await;
    assert_eq!(reply.status, StatusCode::OK);
    reply
}

#[tokio::test]
async fn a_refresh_token_rotates_and_a_reused_one_ends_the_login() {
    let app = app();
    let login = logged_in(&app).await;
    let first = login.cookie("__Host-refresh");
    assert!(
        login
            .cookies
            .iter()
            .any(|c| c.starts_with("__Host-refresh=")
                && c.contains("HttpOnly")
                && c.contains("SameSite=Strict"))
    );

    // Trade it: a new JWT and a new refresh token.
    let rotated = send(&app, post("/refresh", Some(&first), "")).await;
    assert_eq!(rotated.status, StatusCode::OK);
    let second = rotated.cookie("__Host-refresh");
    assert_ne!(first, second);
    let jwt = rotated.cookie("jwt");
    let whoami = Request::get("/whoami")
        .header(header::COOKIE, &jwt)
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, whoami).await.status, StatusCode::OK);

    // The first one again: someone has a copy. The family is revoked, so
    // even the current token stops working.
    assert_eq!(
        send(&app, post("/refresh", Some(&first), "")).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&app, post("/refresh", Some(&second), "")).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn logout_and_a_password_change_end_the_refresh_tokens() {
    let app = app();
    let login = logged_in(&app).await;
    let cookies = format!(
        "{}; {}",
        login.cookie("jwt"),
        login.cookie("__Host-refresh")
    );
    let logout = send(&app, post("/logout", Some(&cookies), "")).await;
    assert_eq!(logout.status, StatusCode::OK);
    assert!(
        logout
            .cookies
            .iter()
            .any(|c| c.starts_with("__Host-refresh=") && c.contains("Max-Age=0"))
    );
    assert_eq!(
        send(
            &app,
            post("/refresh", Some(&login.cookie("__Host-refresh")), "")
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );

    let login = send(&app, post("/login", None, CREDENTIALS)).await;
    let change = json!({ "new_password": "another-good-password" }).to_string();
    let reply = send(
        &app,
        post("/change-password", Some(&login.cookie("jwt")), &change),
    )
    .await;
    assert!(reply.status.is_success(), "{:?}", reply.body);
    assert_eq!(
        send(
            &app,
            post("/refresh", Some(&login.cookie("__Host-refresh")), "")
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn bearer_clients_get_the_tokens_in_the_body_and_send_them_in_headers() {
    let app = app();
    let login = logged_in(&app).await;
    let access = login.body["accessToken"].as_str().unwrap().to_string();
    let refresh = login.body["refreshToken"].as_str().unwrap().to_string();
    assert_eq!(login.body["tokenType"], "Bearer");

    let whoami = Request::get("/whoami")
        .header(header::AUTHORIZATION, format!("Bearer {access}"))
        .body(Body::empty())
        .unwrap();
    let reply = app.clone().oneshot(whoami).await.unwrap();
    assert_eq!(reply.status(), StatusCode::OK);

    // Refresh with the token in the body instead of a cookie.
    let body = json!({ "refreshToken": refresh }).to_string();
    let rotated = send(&app, post("/refresh", None, &body)).await;
    assert_eq!(rotated.status, StatusCode::OK);
    assert_ne!(rotated.body["refreshToken"].as_str().unwrap(), refresh);

    // Garbage is refused.
    let body = json!({ "refreshToken": "not-a-token" }).to_string();
    assert_eq!(
        send(&app, post("/refresh", None, &body)).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_bearer_client_logging_out_ends_its_refresh_token() {
    let app = app();
    let login = logged_in(&app).await;
    let access = login.body["accessToken"].as_str().unwrap().to_string();
    let refresh = login.body["refreshToken"].as_str().unwrap().to_string();

    // No cookies: only the header, as a mobile app would send it.
    let logout = Request::post("/logout")
        .header(header::AUTHORIZATION, format!("Bearer {access}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, logout).await.status, StatusCode::OK);

    let body = json!({ "refreshToken": refresh }).to_string();
    assert_eq!(
        send(&app, post("/refresh", None, &body)).await.status,
        StatusCode::UNAUTHORIZED
    );
}
