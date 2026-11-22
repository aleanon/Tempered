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
        SessionConfig::new("session", 3600),
    )
    .supports_registration()
    .supports_elevation(
        HashMapSessionStore::new(),
        SessionConfig::new("elevated_session", 900),
        |elevated| {
            elevated
                .supports_password_change()
                .supports_account_deletion()
        },
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

/// Log in and elevate, returning a `Cookie` header value carrying both the
/// session and the elevated session.
async fn elevated(app: &Router, email: &str) -> String {
    let session = signed_in(app, email).await;
    let response = app
        .clone()
        .oneshot(post(
            "/elevate",
            Some(&session),
            json!({ "email": email, "password": PASSWORD }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let set_cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    format!("{session}; {}", set_cookie.split(';').next().unwrap())
}

#[tokio::test]
async fn elevated_password_change_works_for_a_session_scheme() {
    let app = app();
    let cookies = elevated(&app, EMAIL).await;

    let response = app
        .clone()
        .oneshot(post(
            "/elevated/change-password",
            Some(&cookies),
            json!({ "new_password": "a-brand-new-password" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // The new password logs in; the old one no longer does.
    let new = json!({ "email": EMAIL, "password": "a-brand-new-password" });
    let old = json!({ "email": EMAIL, "password": PASSWORD });
    let login = |body| app.clone().oneshot(post("/login", None, body));
    assert_eq!(login(new).await.unwrap().status(), StatusCode::OK);
    assert_eq!(login(old).await.unwrap().status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn elevated_account_deletion_works_for_a_session_scheme() {
    let app = app();
    let cookies = elevated(&app, EMAIL).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/elevated/delete-account")
                .header(header::COOKIE, &cookies)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let login = app
        .clone()
        .oneshot(post(
            "/login",
            None,
            json!({ "email": EMAIL, "password": PASSWORD }),
        ))
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn elevated_routes_reject_a_plain_session() {
    let app = app();
    let session = signed_in(&app, EMAIL).await;

    let response = app
        .oneshot(post(
            "/elevated/change-password",
            Some(&session),
            json!({ "new_password": "a-brand-new-password" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
