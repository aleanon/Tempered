//! A password policy applies to every new password: signup, password
//! change and reset (where a refused password leaves the link usable).
//! In-memory stores and `tower::oneshot`.

use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use secrecy::{ExposeSecret, Secret};
use serde_json::{Value, json};
use tempered_adapters::auth_validation::local_jwt_validator::JwtAuthConfig;
use tempered_adapters::authentication::jwt_scheme::JwtScheme;
use tempered_adapters::persistence::{
    HashMapPasswordResetTokenStore, HashMapTokenEpochStore, HashMapUserStore,
    HashSetBannedTokenStore,
};
use tempered_axum::auth_service::auth_service;
use tempered_core::{Email, EmailClient, Password, PasswordPolicy, PasswordRejected};
use tower::ServiceExt; // for `oneshot`

/// Refuses any password containing "acme".
struct NoCompanyName;

#[async_trait::async_trait]
impl PasswordPolicy for NoCompanyName {
    async fn check(&self, _: &Email, password: &Password) -> Result<(), PasswordRejected> {
        if password.as_ref().expose_secret().contains("acme") {
            Err(PasswordRejected("Do not use the company name".to_string()))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Default)]
struct Outbox(Arc<Mutex<Vec<String>>>);

#[async_trait::async_trait]
impl EmailClient for Outbox {
    async fn send_email(&self, _: &Email, _: &str, content: &str) -> Result<(), String> {
        self.0.lock().unwrap().push(content.to_string());
        Ok(())
    }
}

fn app(outbox: &Outbox) -> Router {
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
    .supports_password_reset(HashMapPasswordResetTokenStore::new(), outbox.clone())
    .password_policy(NoCompanyName);
    auth_service(scheme, String::new()).into()
}

async fn post(
    app: &Router,
    path: &str,
    cookie: Option<&str>,
    body: Value,
) -> (StatusCode, Option<String>, Value) {
    let mut request = Request::post(path).header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
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

#[tokio::test]
async fn the_policy_applies_to_signup_change_and_reset() {
    let outbox = Outbox::default();
    let app = app(&outbox);

    let (status, _, body) = post(
        &app,
        "/signup",
        None,
        json!({ "email": "u@example.com", "password": "acme-forever-1", "requires2FA": false }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "Do not use the company name");
    let good =
        json!({ "email": "u@example.com", "password": "correct-horse", "requires2FA": false });
    assert!(post(&app, "/signup", None, good).await.0.is_success());

    let (_, session, _) = post(
        &app,
        "/login",
        None,
        json!({ "email": "u@example.com", "password": "correct-horse" }),
    )
    .await;
    let (status, _, _) = post(
        &app,
        "/change-password",
        session.as_deref(),
        json!({ "new_password": "acme-again-22" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A refused password does not spend the reset link.
    post(
        &app,
        "/password-reset/initiate",
        None,
        json!({ "email": "u@example.com" }),
    )
    .await;
    let token = loop {
        if let Some(t) = outbox.0.lock().unwrap().first().cloned() {
            break t;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    };
    let (status, _, _) = post(
        &app,
        "/password-reset/complete",
        None,
        json!({ "reset_token": token, "new_password": "acme-thrice-333" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, body) = post(
        &app,
        "/password-reset/complete",
        None,
        json!({ "reset_token": token, "new_password": "a-fine-new-one" }),
    )
    .await;
    assert!(status.is_success(), "{status} {body}");
}
