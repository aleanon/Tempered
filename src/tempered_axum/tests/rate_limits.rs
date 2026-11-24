//! Rate limits through the axum service: attempts over a limit get 429 with
//! `Retry-After`, per account and per client address (taken from the
//! connection). In-memory stores and `tower::oneshot`.

use std::net::SocketAddr;

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use secrecy::Secret;
use serde_json::json;
use tempered_adapters::auth_validation::local_jwt_validator::JwtAuthConfig;
use tempered_adapters::authentication::jwt_scheme::JwtScheme;
use tempered_adapters::authentication::rate_limit::{
    Limit, RateLimitGroup, RateLimiter, RateLimits,
};
use tempered_adapters::persistence::{
    HashMapRateLimitStore, HashMapTokenEpochStore, HashMapUserStore, HashSetBannedTokenStore,
};
use tempered_axum::auth_service::auth_service;
use tower::ServiceExt; // for `oneshot`

fn app(limits: RateLimits) -> Router {
    let scheme = JwtScheme::new(
        HashMapUserStore::new(),
        JwtAuthConfig {
            jwt_cookie_name: "jwt".to_string(),
            jwt_secret: Secret::new("a-test-secret-that-is-long-enough".to_string()),
            token_ttl_in_seconds: 3600,
            audience: None,
            issuer: None,
        },
        HashSetBannedTokenStore::new(),
        HashMapTokenEpochStore::new(),
    )
    .supports_registration()
    .rate_limited(RateLimiter::new(HashMapRateLimitStore::new()).limits(limits));
    auth_service(scheme, String::new()).into()
}

/// A login attempt for `email` from `peer`, as axum's connect info presents
/// the connection.
fn login(email: &str, peer: &str) -> Request<Body> {
    let mut request = Request::post("/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "email": email, "password": "not-the-password" }).to_string(),
        ))
        .unwrap();
    let addr: SocketAddr = format!("{peer}:4000").parse().unwrap();
    request.extensions_mut().insert(ConnectInfo(addr));
    request
}

#[tokio::test]
async fn login_attempts_over_the_account_limit_get_429() {
    let app = app(RateLimits::none().per_account(RateLimitGroup::Login, Some(Limit::new(3, 900))));

    for _ in 0..3 {
        let response = app
            .clone()
            .oneshot(login("a@example.com", "203.0.113.7"))
            .await
            .unwrap();
        // Wrong password (or no such account): refused, but counted.
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let response = app
        .clone()
        .oneshot(login("a@example.com", "198.51.100.1"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers().contains_key("retry-after"));

    // The address is counted however it is written.
    let response = app
        .clone()
        .oneshot(login("A@Example.com", "198.51.100.2"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    // Another account is still answered.
    let response = app
        .oneshot(login("b@example.com", "203.0.113.7"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn one_client_spraying_accounts_hits_the_client_limit() {
    let app = app(RateLimits::none().per_client(RateLimitGroup::Login, Some(Limit::new(3, 900))));

    for i in 0..3 {
        let email = format!("user{i}@example.com");
        let response = app
            .clone()
            .oneshot(login(&email, "203.0.113.7"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let response = app
        .clone()
        .oneshot(login("user9@example.com", "203.0.113.7"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    // Another client is not affected.
    let response = app
        .oneshot(login("user9@example.com", "198.51.100.1"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_default_limits_leave_a_normal_login_alone() {
    let app = app(RateLimits::default());
    let signup = Request::post("/signup")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "email": "a@example.com", "password": "correct-horse", "requires2FA": false })
                .to_string(),
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(signup).await.unwrap().status(),
        StatusCode::CREATED
    );

    let mut request = login("a@example.com", "203.0.113.7");
    *request.body_mut() =
        Body::from(json!({ "email": "a@example.com", "password": "correct-horse" }).to_string());
    assert_eq!(app.oneshot(request).await.unwrap().status(), StatusCode::OK);
}
