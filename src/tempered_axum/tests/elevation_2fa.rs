//! `/elevate` holds an account to its second factor, as login does: the
//! password alone answers with a 2FA challenge, and the elevated token comes
//! from `/elevate/verify-2fa` with the mailed code. In-memory stores and
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
use tempered_adapters::authentication::jwt_scheme::JwtScheme;
use tempered_adapters::persistence::{
    HashMapTokenEpochStore, HashMapTwoFaCodeStore, HashMapUserStore, HashSetBannedTokenStore,
};
use tempered_axum::auth_service::auth_service;
use tempered_core::{Email, EmailClient};
use tower::ServiceExt; // for `oneshot`

const PASSWORD: &str = "correct-horse-battery";

/// Keeps every message it is asked to send (the 2FA code is the body).
#[derive(Clone, Default)]
struct Outbox(Arc<Mutex<Vec<String>>>);

impl Outbox {
    fn last(&self) -> String {
        self.0
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("a code was sent")
    }
}

#[async_trait::async_trait]
impl EmailClient for Outbox {
    async fn send_email(&self, _: &Email, _: &str, content: &str) -> Result<(), String> {
        self.0.lock().unwrap().push(content.to_string());
        Ok(())
    }
}

fn config(cookie: &str, secret: &str) -> JwtAuthConfig {
    JwtAuthConfig {
        jwt_cookie_name: cookie.to_string(),
        jwt_secret: Secret::new(secret.to_string()),
        token_ttl_in_seconds: 3600,
        audience: None,
        issuer: None,
    }
}

fn app(outbox: &Outbox) -> Router {
    let scheme = JwtScheme::new(
        HashMapUserStore::new(),
        config("jwt", "a-test-secret-that-is-long-enough"),
        HashSetBannedTokenStore::new(),
        HashMapTokenEpochStore::new(),
    )
    .supports_registration()
    .supports_2fa(HashMapTwoFaCodeStore::new(), outbox.clone())
    .supports_elevation(
        HashSetBannedTokenStore::new(),
        config("elevated_jwt", "an-elevated-test-secret-long-enough"),
        |e| e.supports_password_change(),
    );
    auth_service(scheme, ".".to_string()).into()
}

fn post(path: &str, cookie: Option<&str>, body: Value) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
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
    let body = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, cookie, body)
}

/// Sign up `email` with 2FA and complete a 2FA login; the session cookie.
async fn logged_in(app: &Router, outbox: &Outbox, email: &str) -> String {
    let credentials = json!({ "email": email, "password": PASSWORD, "requires2FA": true });
    let (status, _, _) = send(app, post("/signup", None, credentials.clone())).await;
    assert!(status.is_success());
    let (status, _, body) = send(app, post("/login", None, credentials)).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    let verify = json!({
        "email": email,
        "loginAttemptId": body["loginAttemptId"],
        "2FACode": outbox.last(),
    });
    let (status, cookie, _) = send(app, post("/verify-2fa", None, verify)).await;
    assert_eq!(status, StatusCode::OK);
    cookie.unwrap()
}

#[tokio::test]
async fn the_password_alone_does_not_elevate_a_two_factor_account() {
    let outbox = Outbox::default();
    let app = app(&outbox);
    let session = logged_in(&app, &outbox, "user@example.com").await;

    let elevate = json!({ "email": "user@example.com", "password": PASSWORD });
    let (status, cookie, body) = send(&app, post("/elevate", Some(&session), elevate)).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert!(
        cookie.is_none(),
        "no elevated cookie before the second factor"
    );
    let attempt = body["loginAttemptId"].clone();

    // A wrong code gets nothing.
    let right = outbox.last();
    let wrong = if right == "000000" {
        "000001"
    } else {
        "000000"
    };
    let guess = json!({ "loginAttemptId": attempt, "2FACode": wrong });
    let (status, cookie, _) = send(&app, post("/elevate/verify-2fa", Some(&session), guess)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(cookie.is_none());

    // The mailed code completes the elevation.
    let code = json!({ "loginAttemptId": attempt, "2FACode": right });
    let (status, cookie, _) = send(&app, post("/elevate/verify-2fa", Some(&session), code)).await;
    assert_eq!(status, StatusCode::OK);
    let sudo = cookie.expect("the elevated cookie");
    let (status, _, _) = send(&app, post("/elevated/verify-token", Some(&sudo), json!({}))).await;
    assert_eq!(status, StatusCode::OK);
    let change = json!({ "new_password": "another-long-password" });
    let (status, _, _) = send(&app, post("/elevated/change-password", Some(&sudo), change)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn the_second_step_needs_the_session_of_the_user_it_was_sent_to() {
    let outbox = Outbox::default();
    let app = app(&outbox);
    let victim = logged_in(&app, &outbox, "victim@example.com").await;
    let elevate = json!({ "email": "victim@example.com", "password": PASSWORD });
    let (_, _, body) = send(&app, post("/elevate", Some(&victim), elevate)).await;
    let code = json!({ "loginAttemptId": body["loginAttemptId"], "2FACode": outbox.last() });

    // No session: refused before the code is looked at.
    let (status, _, _) = send(&app, post("/elevate/verify-2fa", None, code.clone())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Someone else's session: the code is checked against *their* account.
    let other = logged_in(&app, &outbox, "other@example.com").await;
    let (status, cookie, _) = send(&app, post("/elevate/verify-2fa", Some(&other), code)).await;
    assert_ne!(status, StatusCode::OK);
    assert!(cookie.is_none());
}
