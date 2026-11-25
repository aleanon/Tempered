//! Users managing their own API keys through the login scheme, and the
//! keys working (with scopes, expiry and last use) against an API-key
//! scheme on the same store. In-memory stores and `tower::oneshot`.

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    middleware::{from_fn, from_fn_with_state},
    routing::get,
};
use secrecy::Secret;
use serde_json::{Value, json};
use tempered_adapters::auth_validation::local_jwt_validator::JwtAuthConfig;
use tempered_adapters::authentication::api_key_scheme::{ApiKeyScheme, Issuance};
use tempered_adapters::authentication::jwt_scheme::JwtScheme;
use tempered_adapters::persistence::{
    HashMapApiKeyStore, HashMapTokenEpochStore, HashMapUserStore, HashSetBannedTokenStore,
};
use tempered_axum::auth_service::auth_service;
use tempered_axum::middleware::{require_scope, validate_token};
use tempered_core::{Email, SupportsApiKeyIssuance};
use tower::ServiceExt;

type Keys = ApiKeyScheme<HashMapApiKeyStore, Issuance>;

fn config(cookie: &str, secret: &str) -> JwtAuthConfig {
    JwtAuthConfig {
        jwt_cookie_name: cookie.to_string(),
        jwt_secret: Secret::new(secret.to_string()),
        token_ttl_in_seconds: 300,
        audience: None,
        issuer: None,
    }
}

/// The account app (JWT, with key management) and a service that accepts
/// the keys, over one key store.
fn apps() -> (Router, Router, Keys) {
    let store = HashMapApiKeyStore::new();
    let accounts = JwtScheme::new(
        HashMapUserStore::new(),
        config("jwt", "a-test-secret-that-is-long-enough"),
        HashSetBannedTokenStore::new(),
        HashMapTokenEpochStore::new(),
    )
    .supports_registration()
    .supports_elevation(
        HashSetBannedTokenStore::new(),
        config("elevated", "another-test-secret-long-enough!"),
        |e| e.supports_account_deletion(),
    )
    .supports_api_key_management(store.clone(), ["read"]);
    let accounts: Router = auth_service(accounts, String::new()).into();

    let keys: Keys = ApiKeyScheme::new(store).supports_issuance();
    let service = Router::new()
        .route("/read", get(|| async { "read" }))
        .layer(from_fn(|req, next| require_scope("read", req, next)))
        .merge(
            Router::new()
                .route("/write", get(|| async { "write" }))
                .layer(from_fn(|req, next| require_scope("write", req, next))),
        )
        .layer(from_fn_with_state(keys.clone(), validate_token::<Keys>))
        .with_state(keys.clone());
    (accounts, service, keys)
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, Option<String>, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .map(|c| c.to_str().unwrap().split(';').next().unwrap().to_string());
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        cookie,
        serde_json::from_slice(&body).unwrap_or(Value::Null),
    )
}

fn json_request(method: &str, path: &str, cookies: &[&str], body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, cookies.join("; "))
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn with_key(path: &str, key: &str) -> Request<Body> {
    Request::get(path)
        .header("x-api-key", key)
        .body(Body::empty())
        .unwrap()
}

/// Sign up, log in and elevate: (session, elevated) cookies.
async fn elevated(app: &Router) -> (String, String) {
    let credentials =
        json!({ "email": "dev@example.com", "password": "correct-horse", "requires2FA": false });
    send(
        app,
        json_request("POST", "/signup", &[], credentials.clone()),
    )
    .await;
    let (_, session, _) = send(app, json_request("POST", "/login", &[], credentials)).await;
    let session = session.unwrap();
    let elevate = json!({ "email": "dev@example.com", "password": "correct-horse" });
    let (status, elevated, _) =
        send(app, json_request("POST", "/elevate", &[&session], elevate)).await;
    assert_eq!(status, StatusCode::OK);
    (session, elevated.unwrap())
}

#[tokio::test]
async fn a_user_issues_uses_lists_and_revokes_a_key() {
    let (accounts, service, _) = apps();
    let (session, elevated) = elevated(&accounts).await;

    // Issuing needs the elevated token.
    let issue = json!({ "scopes": ["read"], "expiresInDays": 30 });
    let (status, _, _) = send(
        &accounts,
        json_request("POST", "/elevated/api-keys", &[&session], issue.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, body) = send(
        &accounts,
        json_request("POST", "/elevated/api-keys", &[&session, &elevated], issue),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let key = body["apiKey"].as_str().unwrap().to_string();
    let id = body["id"].as_str().unwrap().to_string();
    assert!(body["expiresAt"].as_u64().is_some());

    // Users may give their keys only the scopes the app allows.
    let greedy = json!({ "scopes": ["read", "write"] });
    let (status, _, body) = send(
        &accounts,
        json_request("POST", "/elevated/api-keys", &[&session, &elevated], greedy),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // The key works where its scope allows, and only there.
    assert_eq!(
        send(&service, with_key("/read", &key)).await.0,
        StatusCode::OK
    );
    assert_eq!(
        send(&service, with_key("/write", &key)).await.0,
        StatusCode::FORBIDDEN
    );

    // Listed, with its last use, and never the secret.
    let list = Request::get("/api-keys")
        .header(header::COOKIE, &session)
        .body(Body::empty())
        .unwrap();
    let (status, _, body) = send(&accounts, list).await;
    assert_eq!(status, StatusCode::OK);
    let listed = &body["keys"][0];
    assert_eq!(listed["id"], id);
    assert!(listed["lastUsedAt"].as_u64().is_some());
    assert!(!body.to_string().contains(&key));

    // Revoked, it stops working.
    let revoke = json_request(
        "DELETE",
        &format!("/elevated/api-keys/{id}"),
        &[&session, &elevated],
        json!({}),
    );
    assert_eq!(send(&accounts, revoke).await.0, StatusCode::OK);
    assert_eq!(
        send(&service, with_key("/read", &key)).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn an_expired_key_is_refused() {
    let (_, service, keys) = apps();
    let owner = Email::try_from(Secret::new("dev@example.com".to_string())).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (_, key) = keys
        .issue_api_key_until(owner, vec!["read".to_string()], Some(now - 1))
        .await
        .unwrap();
    assert_eq!(
        send(&service, with_key("/read", &key)).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn deleting_the_account_deletes_its_keys() {
    let (accounts, service, _) = apps();
    let (session, elevated) = elevated(&accounts).await;
    let issue = json!({ "scopes": ["read"] });
    let (_, _, body) = send(
        &accounts,
        json_request("POST", "/elevated/api-keys", &[&session, &elevated], issue),
    )
    .await;
    let key = body["apiKey"].as_str().unwrap().to_string();

    let delete = json_request(
        "DELETE",
        "/elevated/delete-account",
        &[&session, &elevated],
        json!({}),
    );
    assert!(send(&accounts, delete).await.0.is_success());
    assert_eq!(
        send(&service, with_key("/read", &key)).await.0,
        StatusCode::UNAUTHORIZED
    );
}
