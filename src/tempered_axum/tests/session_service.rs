//! `auth_service` serves a `SessionScheme` end to end.
//!
//! JWT and session are the same `CredentialScheme` over different token
//! strategies, but their validators produce different claims types, so routes
//! that read the logged-in user must not assume JWT claims. These tests use
//! in-memory stores and `tower::oneshot`, so they need no containers.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use serde_json::json;
use tempered_adapters::authentication::session_scheme::{SessionConfig, SessionScheme};
use tempered_adapters::persistence::{HashMapSessionStore, HashMapUserStore};
use tempered_axum::auth_service::auth_service;
use tower::ServiceExt; // for `oneshot`

const EMAIL: &str = "user@example.com";
const PASSWORD: &str = "correct-horse-battery";

fn app() -> Router {
    let scheme = SessionScheme::new(
        HashMapUserStore::new(),
        HashMapSessionStore::new(),
        SessionConfig {
            cookie_name: "session".to_string(),
            ttl_in_seconds: 3600,
        },
    )
    .supports_registration()
    .supports_elevation(
        HashMapSessionStore::new(),
        SessionConfig {
            cookie_name: "elevated_session".to_string(),
            ttl_in_seconds: 900,
        },
        |elevated| elevated,
    )
    .build();

    auth_service(scheme, ".".to_string()).into()
}

fn post(uri: &str, cookie: Option<&str>, body: serde_json::Value) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    request.body(Body::from(body.to_string())).unwrap()
}

/// Sign up and log in, returning the `name=value` session cookie.
async fn signed_in(app: &Router, email: &str) -> String {
    let credentials = json!({ "email": email, "password": PASSWORD, "requires2FA": false });
    let signup = app
        .clone()
        .oneshot(post("/signup", None, credentials.clone()))
        .await
        .unwrap();
    assert!(signup.status().is_success(), "signup: {}", signup.status());

    let login = app
        .clone()
        .oneshot(post("/login", None, credentials))
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let set_cookie = login.headers()[header::SET_COOKIE].to_str().unwrap();
    set_cookie.split(';').next().unwrap().to_string()
}

#[tokio::test]
async fn elevate_works_for_the_session_owner() {
    let app = app();
    let cookie = signed_in(&app, EMAIL).await;

    let response = app
        .oneshot(post(
            "/elevate",
            Some(&cookie),
            json!({ "email": EMAIL, "password": PASSWORD }),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .starts_with("elevated_session=")
    );
}

#[tokio::test]
async fn elevate_rejects_another_users_credentials() {
    let app = app();
    signed_in(&app, "victim@example.com").await;
    let attacker_cookie = signed_in(&app, "attacker@example.com").await;

    // The attacker is logged in as themselves but knows the victim's password.
    let response = app
        .oneshot(post(
            "/elevate",
            Some(&attacker_cookie),
            json!({ "email": "victim@example.com", "password": PASSWORD }),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn elevate_requires_a_session() {
    let response = app()
        .oneshot(post(
            "/elevate",
            None,
            json!({ "email": EMAIL, "password": PASSWORD }),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
