//! The verified route tier: login routes, then routes that also need a
//! verified email address, then elevated routes.
//!
//! With email verification, a logged-in user whose address is not verified can
//! log out, check their token and ask for another link, but cannot change a
//! credential or reach `.verified_router(..)` routes until they verify.
//! In-memory stores and `tower::oneshot`; no containers.

use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::get,
};
use secrecy::Secret;
use serde_json::json;
use tempered_adapters::auth_validation::local_jwt_validator::JwtAuthConfig;
use tempered_adapters::authentication::jwt_scheme::JwtScheme;
use tempered_adapters::persistence::{
    HashMapEmailVerificationTokenStore, HashMapTokenEpochStore, HashMapUserStore,
    HashSetBannedTokenStore,
};
use tempered_axum::auth_service::auth_service;
use tempered_core::{Email, EmailClient};
use tower::ServiceExt; // for `oneshot`

const EMAIL: &str = "user@example.com";
const PASSWORD: &str = "correct-horse-battery";

/// Keeps every verification link it is asked to send (the token is the body).
#[derive(Clone, Default)]
struct Outbox(Arc<Mutex<Vec<String>>>);

impl Outbox {
    /// Every mail sent, once there are at least `n`. Signup mails go out
    /// after the response, so a test waits for them.
    async fn sent(&self, n: usize) -> Vec<String> {
        for _ in 0..1000 {
            let sent = self.0.lock().unwrap().clone();
            if sent.len() >= n {
                return sent;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        panic!("fewer than {n} mails were sent");
    }
}

#[async_trait::async_trait]
impl EmailClient for Outbox {
    async fn send_email(&self, _: &Email, _: &str, content: &str) -> Result<(), String> {
        self.0.lock().unwrap().push(content.to_string());
        Ok(())
    }
}

fn jwt_config() -> JwtAuthConfig {
    JwtAuthConfig {
        jwt_cookie_name: "jwt".to_string(),
        jwt_secret: Secret::new("a-test-secret-that-is-long-enough".to_string()),
        token_ttl_in_seconds: 3600,
        audience: None,
        issuer: None,
    }
}

fn app(outbox: &Outbox) -> Router {
    let scheme = JwtScheme::new(
        HashMapUserStore::new(),
        jwt_config(),
        HashSetBannedTokenStore::new(),
        HashMapTokenEpochStore::new(),
    )
    .supports_registration()
    .supports_password_change()
    .supports_account_deletion()
    .supports_email_verification(HashMapEmailVerificationTokenStore::new(), outbox.clone())
    .build();

    auth_service(scheme, ".".to_string())
        .validated_router(Router::new().route("/profile", get(|| async { "profile" })))
        .verified_router(Router::new().route("/billing", get(|| async { "billing" })))
        .into()
}

fn request(
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    body: serde_json::Value,
) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    request.body(Body::from(body.to_string())).unwrap()
}

async fn status(app: &Router, request: Request<Body>) -> StatusCode {
    app.clone().oneshot(request).await.unwrap().status()
}

/// Sign up and log in, returning the `name=value` auth cookie.
async fn signed_in(app: &Router) -> String {
    signed_in_as(app, EMAIL).await
}

/// Sign up `email` and log in, returning the auth cookie.
async fn signed_in_as(app: &Router, email: &str) -> String {
    let credentials = json!({ "email": email, "password": PASSWORD, "requires2FA": false });
    let signup = status(app, request("POST", "/signup", None, credentials.clone())).await;
    assert!(signup.is_success(), "signup: {signup}");

    let login = app
        .clone()
        .oneshot(request("POST", "/login", None, credentials))
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let set_cookie = login.headers()[header::SET_COOKIE].to_str().unwrap();
    set_cookie.split(';').next().unwrap().to_string()
}

#[tokio::test]
async fn an_unverified_user_is_logged_in_but_kept_out_of_the_verified_tier() {
    let outbox = Outbox::default();
    let app = app(&outbox);
    let cookie = signed_in(&app).await;
    assert_eq!(
        outbox.sent(1).await.len(),
        1,
        "signup sends the verification link"
    );

    // Login tier: open.
    let profile = request("GET", "/profile", Some(&cookie), json!({}));
    assert_eq!(status(&app, profile).await, StatusCode::OK);
    let verify_token = request("POST", "/verify-token", Some(&cookie), json!({}));
    assert_eq!(status(&app, verify_token).await, StatusCode::OK);

    // Verified tier: the app's own route and the library's credential change.
    let billing = request("GET", "/billing", Some(&cookie), json!({}));
    assert_eq!(status(&app, billing).await, StatusCode::FORBIDDEN);
    let change = request(
        "POST",
        "/change-password",
        Some(&cookie),
        json!({ "new_password": "another-long-password" }),
    );
    assert_eq!(status(&app, change).await, StatusCode::FORBIDDEN);

    // Without a login, the verified tier answers like any login route.
    let anonymous = request("GET", "/billing", None, json!({}));
    assert_eq!(status(&app, anonymous).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn verifying_opens_the_verified_tier_without_a_new_login() {
    let outbox = Outbox::default();
    let app = app(&outbox);
    let cookie = signed_in(&app).await;

    // A lost email: ask for another link from the login tier.
    let resend = request("POST", "/verify-email/resend", Some(&cookie), json!({}));
    assert_eq!(status(&app, resend).await, StatusCode::OK);
    let sent = outbox.sent(2).await;
    assert_eq!(sent.len(), 2);

    // The token alone is not enough: verifying needs the account's login.
    let anonymous = request("POST", "/verify-email", None, json!({ "token": sent[1] }));
    assert_eq!(status(&app, anonymous).await, StatusCode::UNAUTHORIZED);
    let verify = request(
        "POST",
        "/verify-email",
        Some(&cookie),
        json!({ "token": sent[1] }),
    );
    assert_eq!(status(&app, verify).await, StatusCode::OK);

    // The same cookie now reaches the verified tier: checked per request.
    let billing = request("GET", "/billing", Some(&cookie), json!({}));
    assert_eq!(status(&app, billing).await, StatusCode::OK);
    let change = request(
        "POST",
        "/change-password",
        Some(&cookie),
        json!({ "new_password": "another-long-password" }),
    );
    assert_eq!(status(&app, change).await, StatusCode::OK);

    // Verified, resending sends nothing more.
    let fresh = signed_in_again(&app).await;
    let resend = request("POST", "/verify-email/resend", Some(&fresh), json!({}));
    assert_eq!(status(&app, resend).await, StatusCode::OK);
    assert_eq!(outbox.sent(2).await.len(), 2);
}

#[tokio::test]
async fn an_unverified_user_can_still_delete_the_account() {
    // Someone who signed up with a mistyped address can remove it.
    let outbox = Outbox::default();
    let app = app(&outbox);
    let cookie = signed_in(&app).await;

    let delete = request("DELETE", "/delete-account", Some(&cookie), json!({}));
    assert!(status(&app, delete).await.is_success());
}

#[tokio::test]
async fn the_inbox_owner_cannot_verify_an_account_someone_else_created() {
    // An attacker signs up with the victim's address; signup mails the link
    // to the victim. The victim, logged in to an account of their own, opens
    // it. The attacker's account must stay unproven.
    let outbox = Outbox::default();
    let app = app(&outbox);
    let attackers = signed_in(&app).await;
    let link = outbox.sent(1).await[0].clone();

    let victims = signed_in_as(&app, "victim-own@example.com").await;
    let verify = request(
        "POST",
        "/verify-email",
        Some(&victims),
        json!({ "token": link }),
    );
    assert_eq!(status(&app, verify).await, StatusCode::BAD_REQUEST);

    let billing = request("GET", "/billing", Some(&attackers), json!({}));
    assert_eq!(status(&app, billing).await, StatusCode::FORBIDDEN);
    // The token was spent by the failed attempt.
    let verify = request(
        "POST",
        "/verify-email",
        Some(&attackers),
        json!({ "token": link }),
    );
    assert_eq!(status(&app, verify).await, StatusCode::BAD_REQUEST);
}

/// Log in again (the password change revoked the earlier cookie).
async fn signed_in_again(app: &Router) -> String {
    let credentials = json!({ "email": EMAIL, "password": "another-long-password" });
    let login = app
        .clone()
        .oneshot(request("POST", "/login", None, credentials))
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let set_cookie = login.headers()[header::SET_COOKIE].to_str().unwrap();
    set_cookie.split(';').next().unwrap().to_string()
}
