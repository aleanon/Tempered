//! Passwordless login by email through the axum service: a mailed code or
//! link logs in; the start answers the same for unknown addresses; a 2FA
//! account is still asked for its second factor. In-memory stores and
//! `tower::oneshot`.

use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use secrecy::Secret;
use serde_json::{Value, json};
use tempered_adapters::auth_validation::local_jwt_validator::JwtAuthConfig;
use tempered_adapters::authentication::credential_scheme::EmailLogin;
use tempered_adapters::authentication::jwt_scheme::JwtScheme;
use tempered_adapters::persistence::{
    HashMapTokenEpochStore, HashMapTwoFaCodeStore, HashMapUserStore, HashSetBannedTokenStore,
};
use tempered_axum::auth_service::auth_service;
use tempered_core::{Email, EmailClient};
use tower::ServiceExt; // for `oneshot`

#[derive(Clone, Default)]
struct Outbox(Arc<Mutex<Vec<(String, String)>>>);

impl Outbox {
    /// Mail `n`, waiting for it (it is sent after the response).
    async fn mail(&self, n: usize) -> Option<(String, String)> {
        for _ in 0..200 {
            if let Some(mail) = self.0.lock().unwrap().get(n).cloned() {
                return Some(mail);
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        None
    }
}

#[async_trait::async_trait]
impl EmailClient for Outbox {
    async fn send_email(&self, to: &Email, _: &str, content: &str) -> Result<(), String> {
        use secrecy::ExposeSecret;
        self.0
            .lock()
            .unwrap()
            .push((to.as_ref().expose_secret().clone(), content.to_string()));
        Ok(())
    }
}

fn app(outbox: &Outbox, login: EmailLogin) -> Router {
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
    .supports_2fa(HashMapTwoFaCodeStore::new(), outbox.clone())
    .supports_email_login(login);
    auth_service(scheme, String::new()).into()
}

async fn post(app: &Router, path: &str, body: Value) -> (StatusCode, Option<String>, Value) {
    let request = Request::post(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .map(|c| c.to_str().unwrap().to_string());
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        cookie,
        serde_json::from_slice(&body).unwrap_or(Value::Null),
    )
}

async fn sign_up(app: &Router, email: &str, two_fa: bool) {
    let body = json!({ "email": email, "password": "correct-horse", "requires2FA": two_fa });
    assert!(post(app, "/signup", body).await.0.is_success());
}

#[tokio::test]
async fn a_mailed_code_logs_in_once() {
    let outbox = Outbox::default();
    let app = app(&outbox, EmailLogin::code());
    sign_up(&app, "user@example.com", false).await;

    let (status, _, body) = post(
        &app,
        "/email-login/start",
        json!({ "email": "user@example.com" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let attempt = body["loginAttemptId"].clone();
    let (_, code) = outbox.mail(0).await.expect("a code was mailed");

    let verify = json!({ "email": "user@example.com", "loginAttemptId": attempt, "code": code });
    let (status, cookie, _) = post(&app, "/email-login/verify", verify.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(cookie.unwrap().starts_with("jwt="));
    // Single use.
    assert_eq!(
        post(&app, "/email-login/verify", verify).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn an_unknown_address_gets_the_same_answer_and_no_mail() {
    let outbox = Outbox::default();
    let app = app(&outbox, EmailLogin::code());
    let (status, _, body) = post(
        &app,
        "/email-login/start",
        json!({ "email": "nobody@example.com" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["loginAttemptId"].is_string());
    assert!(outbox.mail(0).await.is_none());
}

#[tokio::test]
async fn a_link_carries_the_code_to_the_apps_page() {
    let outbox = Outbox::default();
    let app = app(
        &outbox,
        EmailLogin::link("https://app.example.com/login/email"),
    );
    sign_up(&app, "user@example.com", false).await;
    post(
        &app,
        "/email-login/start",
        json!({ "email": "user@example.com" }),
    )
    .await;
    let (_, content) = outbox.mail(0).await.unwrap();
    let link = content
        .split_whitespace()
        .find(|w| w.starts_with("https://"))
        .unwrap();
    let url = url::Url::parse(link).unwrap();
    assert_eq!(url.path(), "/login/email");
    let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();

    // The page posts what the link carries.
    let verify = json!({
        "email": query["email"], "loginAttemptId": query["loginAttemptId"], "code": query["code"],
    });
    assert_eq!(
        post(&app, "/email-login/verify", verify).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_two_factor_account_is_still_asked_for_its_second_factor() {
    let outbox = Outbox::default();
    let app = app(&outbox, EmailLogin::code());
    sign_up(&app, "user@example.com", true).await;
    let (_, _, body) = post(
        &app,
        "/email-login/start",
        json!({ "email": "user@example.com" }),
    )
    .await;
    let (_, code) = outbox.mail(0).await.unwrap();
    let verify = json!({ "email": "user@example.com", "loginAttemptId": body["loginAttemptId"], "code": code });
    let (status, cookie, body) = post(&app, "/email-login/verify", verify).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert!(cookie.is_none());
    assert!(body["loginAttemptId"].is_string());
}
