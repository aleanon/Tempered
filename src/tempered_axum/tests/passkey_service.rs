//! Passkey routes: who may enroll a passkey, and for which account.
//!
//! Enrolling a passkey grants the ability to log in as that user, so the two
//! registration routes must require a session and must enroll for the session's
//! owner — never for an email named in the request. These tests pin that down
//! at the HTTP level. In-memory stores and `tower::oneshot`; no containers.

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
    routing::get,
};
use secrecy::{ExposeSecret, Secret};
use serde_json::{Value, json};
use tempered_adapters::auth_validation::local_jwt_validator::{Claims, JwtAuthConfig};
use tempered_adapters::authentication::jwt_scheme::JwtScheme;
use tempered_adapters::passkey::PasskeyFlow;
use tempered_adapters::persistence::{
    HashMapChallengeStore, HashMapPasskeyCredentialStore, HashMapTokenEpochStore, HashMapUserStore,
    HashSetBannedTokenStore,
};
use tempered_axum::auth_service::auth_service;
use tempered_core::{
    CredentialId, Email, PasskeyCredential, VerifiedAssertion, VerifiedRegistration,
    WebAuthnChallenge, WebAuthnError, WebAuthnVerifier,
};
use tower::ServiceExt; // for `oneshot`

const PASSWORD: &str = "correct-horse-battery";
const VICTIM: &str = "victim@example.com";
const ATTACKER: &str = "attacker@example.com";

/// No cryptography: accepts whatever credential id the "authenticator" sends.
/// The routes' authorization, not the ceremony's crypto, is under test.
#[derive(Clone)]
struct MockVerifier;

impl WebAuthnVerifier for MockVerifier {
    fn start_registration(&self, _email: &Email, challenge: &WebAuthnChallenge) -> Value {
        json!({ "challenge": challenge.as_str() })
    }

    fn verify_registration(
        &self,
        _challenge: &WebAuthnChallenge,
        response: &Value,
    ) -> Result<VerifiedRegistration, WebAuthnError> {
        let id = response["id"]
            .as_str()
            .ok_or_else(|| WebAuthnError::Malformed("no id".into()))?;
        Ok(VerifiedRegistration {
            credential_id: CredentialId(id.to_string()),
            public_key: vec![1, 2, 3],
            sign_count: 0,
        })
    }

    fn start_authentication(
        &self,
        _allowed: &[CredentialId],
        challenge: &WebAuthnChallenge,
    ) -> Value {
        json!({ "challenge": challenge.as_str() })
    }

    fn verify_authentication(
        &self,
        _challenge: &WebAuthnChallenge,
        _response: &Value,
        stored: &PasskeyCredential,
    ) -> Result<VerifiedAssertion, WebAuthnError> {
        Ok(VerifiedAssertion {
            credential_id: stored.credential_id.clone(),
            new_sign_count: stored.sign_count + 1,
        })
    }
}

async fn whoami(Extension(claims): Extension<Claims>) -> String {
    claims.sub.expose_secret().clone()
}

fn app() -> Router {
    let flow = PasskeyFlow::new(
        HashMapPasskeyCredentialStore::new(),
        HashMapChallengeStore::new(),
        MockVerifier,
    );
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
    .supports_passkeys(flow)
    .build();

    auth_service(scheme, ".".to_string())
        .validated_router(Router::new().route("/whoami", get(whoami)))
        .into()
}

async fn post(app: &Router, uri: &str, cookie: Option<&str>, body: Value) -> Response {
    let mut request = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    app.clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

async fn json_body(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// The `name=value` pair of the auth cookie a response sets.
fn auth_cookie(response: &Response) -> String {
    let set_cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    set_cookie.split(';').next().unwrap().to_string()
}

/// Sign up and password-login, returning the session cookie.
async fn signed_in(app: &Router, email: &str) -> String {
    let credentials = json!({ "email": email, "password": PASSWORD, "requires2FA": false });
    let signup = post(app, "/signup", None, credentials.clone()).await;
    assert!(signup.status().is_success(), "signup: {}", signup.status());
    let login = post(app, "/login", None, credentials).await;
    assert_eq!(login.status(), StatusCode::OK);
    auth_cookie(&login)
}

/// Enroll credential `cred_id` using `cookie`'s session; `body` is sent to
/// `register/start` (the route must ignore it).
async fn enroll(app: &Router, cookie: &str, start_body: Value, cred_id: &str) {
    let start = post(app, "/passkey/register/start", Some(cookie), start_body).await;
    assert_eq!(start.status(), StatusCode::OK);
    let challenge = json_body(start).await["challenge"].clone();

    let finish = post(
        app,
        "/passkey/register/finish",
        Some(cookie),
        json!({ "challenge": challenge, "response": { "id": cred_id } }),
    )
    .await;
    assert_eq!(finish.status(), StatusCode::OK);
}

/// Run the passkey login ceremony for `cred_id`, returning the final response.
async fn passkey_login(app: &Router, email: Option<&str>, cred_id: &str) -> Response {
    let start = post(app, "/passkey/login/start", None, json!({ "email": email })).await;
    assert_eq!(start.status(), StatusCode::OK);
    let challenge = json_body(start).await["challenge"].clone();

    post(
        app,
        "/passkey/login/finish",
        None,
        json!({ "challenge": challenge, "response": { "id": cred_id } }),
    )
    .await
}

async fn whoami_of(app: &Router, cookie: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/whoami")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn registration_requires_a_session() {
    let app = app();
    signed_in(&app, VICTIM).await;

    // No cookie: an anonymous caller naming the victim's email gets nowhere.
    let start = post(
        &app,
        "/passkey/register/start",
        None,
        json!({ "email": VICTIM }),
    )
    .await;
    assert_eq!(start.status(), StatusCode::UNAUTHORIZED);

    let finish = post(
        &app,
        "/passkey/register/finish",
        None,
        json!({ "challenge": "anything", "response": { "id": "cred-evil" } }),
    )
    .await;
    assert_eq!(finish.status(), StatusCode::UNAUTHORIZED);

    // And nothing was enrolled: the credential cannot log in.
    let login = passkey_login(&app, Some(VICTIM), "cred-evil").await;
    assert_eq!(login.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enrolled_passkey_logs_in_as_its_owner() {
    let app = app();
    let cookie = signed_in(&app, VICTIM).await;
    enroll(&app, &cookie, json!({}), "cred-victim").await;

    let login = passkey_login(&app, Some(VICTIM), "cred-victim").await;
    assert_eq!(login.status(), StatusCode::OK);
    assert_eq!(whoami_of(&app, &auth_cookie(&login)).await, VICTIM);
}

#[tokio::test]
async fn an_email_in_the_request_body_is_ignored() {
    let app = app();
    signed_in(&app, VICTIM).await;
    let attacker_cookie = signed_in(&app, ATTACKER).await;

    // The attacker is logged in as themselves and asks to enroll for the victim.
    enroll(
        &app,
        &attacker_cookie,
        json!({ "email": VICTIM }),
        "cred-evil",
    )
    .await;

    // The credential belongs to the attacker's own account, whatever email the
    // login ceremony is started with.
    let login = passkey_login(&app, Some(VICTIM), "cred-evil").await;
    assert_eq!(login.status(), StatusCode::OK);
    assert_eq!(whoami_of(&app, &auth_cookie(&login)).await, ATTACKER);
}

#[tokio::test]
async fn a_ceremony_cannot_be_finished_from_another_account() {
    let app = app();
    let victim_cookie = signed_in(&app, VICTIM).await;
    let attacker_cookie = signed_in(&app, ATTACKER).await;

    // The victim starts enrolling; the attacker learns the challenge.
    let start = post(
        &app,
        "/passkey/register/start",
        Some(&victim_cookie),
        json!({}),
    )
    .await;
    let challenge = json_body(start).await["challenge"].clone();

    let finish = post(
        &app,
        "/passkey/register/finish",
        Some(&attacker_cookie),
        json!({ "challenge": challenge, "response": { "id": "cred-evil" } }),
    )
    .await;
    assert_eq!(finish.status(), StatusCode::BAD_REQUEST);

    let login = passkey_login(&app, Some(VICTIM), "cred-evil").await;
    assert_eq!(login.status(), StatusCode::UNAUTHORIZED);
}
