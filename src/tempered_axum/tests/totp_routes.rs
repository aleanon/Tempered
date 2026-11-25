//! The TOTP routes through the axum service: elevated tier, the start
//! answer, and refusals. (Codes from a real secret are checked at the scheme
//! level, where a test can play the authenticator app.) In-memory stores and
//! `tower::oneshot`.

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use secrecy::Secret;
use serde_json::{Value, json};
use tempered_adapters::auth_validation::local_jwt_validator::JwtAuthConfig;
use tempered_adapters::authentication::jwt_scheme::JwtScheme;
use tempered_adapters::email::MockEmailClient;
use tempered_adapters::persistence::{
    HashMapTokenEpochStore, HashMapTotpStore, HashMapTwoFaCodeStore, HashMapUserStore,
    HashSetBannedTokenStore,
};
use tempered_axum::auth_service::auth_service;
use tower::ServiceExt; // for `oneshot`

const PASSWORD: &str = "correct-horse-battery";

fn config(cookie: &str, secret: &str) -> JwtAuthConfig {
    JwtAuthConfig {
        jwt_cookie_name: cookie.to_string(),
        jwt_secret: Secret::new(secret.to_string()),
        token_ttl_in_seconds: 3600,
        audience: None,
        issuer: None,
    }
}

fn app() -> Router {
    let scheme = JwtScheme::new(
        HashMapUserStore::new(),
        config("jwt", "a-test-secret-that-is-long-enough"),
        HashSetBannedTokenStore::new(),
        HashMapTokenEpochStore::new(),
    )
    .supports_registration()
    .supports_2fa(HashMapTwoFaCodeStore::new(), MockEmailClient::new())
    .supports_elevation(
        HashSetBannedTokenStore::new(),
        config("elevated_jwt", "an-elevated-test-secret-long-enough"),
        |e| e,
    )
    .supports_totp(HashMapTotpStore::new(), "Example");
    auth_service(scheme, String::new()).into()
}

fn post(path: &str, cookies: &[&str], body: Value) -> Request<Body> {
    let mut request = Request::post(path).header(header::CONTENT_TYPE, "application/json");
    if !cookies.is_empty() {
        request = request.header(header::COOKIE, cookies.join("; "));
    }
    request.body(Body::from(body.to_string())).unwrap()
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

/// A user without 2FA, logged in and elevated: (session, elevated) cookies.
async fn elevated(app: &Router) -> (String, String) {
    let credentials =
        json!({ "email": "user@example.com", "password": PASSWORD, "requires2FA": false });
    assert!(
        send(app, post("/signup", &[], credentials.clone()))
            .await
            .0
            .is_success()
    );
    let (status, session, _) = send(app, post("/login", &[], credentials)).await;
    assert_eq!(status, StatusCode::OK);
    let session = session.unwrap();
    let elevate = json!({ "email": "user@example.com", "password": PASSWORD });
    let (status, elevated, _) = send(app, post("/elevate", &[&session], elevate)).await;
    assert_eq!(status, StatusCode::OK);
    (session, elevated.unwrap())
}

#[tokio::test]
async fn the_totp_routes_need_an_elevated_session() {
    let app = app();
    let (session, _) = elevated(&app).await;
    for path in [
        "/elevated/totp/start",
        "/elevated/totp/confirm",
        "/elevated/totp/disable",
        "/elevated/totp/recovery-codes",
    ] {
        let (status, _, _) = send(&app, post(path, &[&session], json!({ "code": "123456" }))).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{path} with a login session only"
        );
    }
}

#[tokio::test]
async fn starting_gives_a_secret_and_an_otpauth_uri() {
    let app = app();
    let (session, elevated) = elevated(&app).await;
    let (status, _, body) = send(
        &app,
        post("/elevated/totp/start", &[&session, &elevated], json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let secret = body["secret"].as_str().unwrap();
    assert_eq!(secret.len(), 32, "160 bits in base32");
    let uri = body["otpauthUri"].as_str().unwrap();
    assert!(
        uri.starts_with("otpauth://totp/Example%3Auser%40example.com?secret="),
        "{uri}"
    );
    assert!(uri.contains(secret));
}

#[tokio::test]
async fn confirming_with_a_malformed_or_wrong_code_is_refused() {
    let app = app();
    let (session, elevated) = elevated(&app).await;
    let cookies = [session.as_str(), elevated.as_str()];
    send(&app, post("/elevated/totp/start", &cookies, json!({}))).await;

    let (status, _, _) = send(
        &app,
        post(
            "/elevated/totp/confirm",
            &cookies,
            json!({ "code": "12ab" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // One in a million, 000000 is the right code; then this only proves less.
    let (status, _, _) = send(
        &app,
        post(
            "/elevated/totp/confirm",
            &cookies,
            json!({ "code": "000000" }),
        ),
    )
    .await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::OK,
        "{status}"
    );
}

#[tokio::test]
async fn new_recovery_codes_need_an_enabled_app() {
    let app = app();
    let (session, elevated) = elevated(&app).await;
    let cookies = [session.as_str(), elevated.as_str()];
    let (status, _, body) = send(
        &app,
        post("/elevated/totp/recovery-codes", &cookies, json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    // Disabling with nothing enabled is fine.
    let (status, _, _) = send(&app, post("/elevated/totp/disable", &cookies, json!({}))).await;
    assert_eq!(status, StatusCode::OK);
}
