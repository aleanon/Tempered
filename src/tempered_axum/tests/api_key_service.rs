//! `auth_service` works for `ApiKeyScheme` (Phase 4D).
//!
//! An API-key scheme has no credential routes, so it auto-wires nothing — but
//! `auth_service` still serves it: a router attached via `validated_router` is
//! protected by the scheme's key validator, exactly as for a JWT scheme. These
//! tests use in-memory stores and `tower::oneshot`, so they need no containers.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use tempered_adapters::authentication::api_key_scheme::ApiKeyScheme;
use tempered_adapters::persistence::HashMapApiKeyStore;
use tempered_axum::auth_service::auth_service;
use tempered_core::{Email, SupportsApiKeyIssuance};
use tower::ServiceExt; // for `oneshot`

fn owner() -> Email {
    Email::try_from(secrecy::Secret::new("demo@service.example".to_string())).unwrap()
}

/// Build an `auth_service`-wired router for an issuance-enabled API-key scheme,
/// with a single protected `/protected` route, and return it alongside a freshly
/// minted valid key.
async fn app_with_key() -> (Router, String) {
    let scheme = ApiKeyScheme::new(HashMapApiKeyStore::new()).supports_issuance();
    let (_id, key) = scheme
        .issue_api_key(owner(), vec!["read".to_string()])
        .await
        .unwrap();

    // `.into()` builds the fully-wired axum Router — this is the call that did
    // not compile before ApiKeyScheme implemented AutoWire.
    let router: Router = auth_service(scheme, ".".to_string())
        .validated_router(Router::new().route("/protected", get(|| async { "authenticated" })))
        .into();

    (router, key)
}

#[tokio::test]
async fn protected_route_allows_a_valid_key() {
    let (app, key) = app_with_key().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header("x-api-key", key)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn protected_route_rejects_a_missing_key() {
    let (app, _key) = app_with_key().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn protected_route_rejects_a_wellformed_but_unknown_key() {
    let (app, _key) = app_with_key().await;

    // `prefix.secret` shape but an unknown prefix → InvalidKey → 401.
    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header("x-api-key", "deadbeef.cafebabe")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn protected_route_rejects_a_malformed_key() {
    let (app, _key) = app_with_key().await;

    // No `prefix.secret` structure → Malformed → 400.
    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header("x-api-key", "not-a-real-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
