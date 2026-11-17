//! Passkey routes: who may enroll a passkey, and for which account.
//!
//! Enrolling a passkey grants the ability to log in as that user, so the two
//! registration routes must require a session and must enroll for the session's
//! owner — never for an email named in the request. These tests pin that down
//! at the HTTP level. In-memory stores and `tower::oneshot`; no containers.

use std::sync::atomic::{AtomicU64, Ordering};

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
    CeremonyStart, CeremonyState, CredentialId, Email, PasskeyCredential, VerifiedAssertion,
    VerifiedRegistration, WebAuthnError, WebAuthnVerifier,
};
use tower::ServiceExt; // for `oneshot`

const PASSWORD: &str = "correct-horse-battery";
const VICTIM: &str = "victim@example.com";
const ATTACKER: &str = "attacker@example.com";

/// No cryptography: accepts whatever credential id the "authenticator" sends,
/// as long as the response echoes the challenge this verifier issued for the
/// ceremony. The routes' authorization, not the crypto, is under test.
#[derive(Clone)]
struct MockVerifier;

static NEXT_CHALLENGE: AtomicU64 = AtomicU64::new(1);

fn start() -> CeremonyStart {
    let challenge = format!(
        "challenge-{}",
        NEXT_CHALLENGE.fetch_add(1, Ordering::Relaxed)
    );
    CeremonyStart {
        options: json!({ "challenge": challenge }),
        state: CeremonyState(challenge.into_bytes()),
    }
}

fn check_challenge(state: &CeremonyState, response: &Value) -> Result<(), WebAuthnError> {
    if response["challenge"].as_str().map(str::as_bytes) == Some(state.0.as_slice()) {
        Ok(())
    } else {
        Err(WebAuthnError::Verification("challenge mismatch".into()))
    }
}

impl WebAuthnVerifier for MockVerifier {
    fn start_registration(
        &self,
        _email: &Email,
        _existing: &[PasskeyCredential],
    ) -> Result<CeremonyStart, WebAuthnError> {
        Ok(start())
    }

    fn finish_registration(
        &self,
        state: &CeremonyState,
        response: &Value,
    ) -> Result<VerifiedRegistration, WebAuthnError> {
        check_challenge(state, response)?;
        let id = response["id"]
            .as_str()
            .ok_or_else(|| WebAuthnError::Malformed("no id".into()))?;
        Ok(VerifiedRegistration {
            credential_id: CredentialId(id.to_string()),
            credential_data: vec![1, 2, 3],
            sign_count: 0,
        })
    }

    fn start_authentication(
        &self,
        _allowed: &[PasskeyCredential],
    ) -> Result<CeremonyStart, WebAuthnError> {
        Ok(start())
    }

    fn finish_authentication(
        &self,
        state: &CeremonyState,
        response: &Value,
        stored: &PasskeyCredential,
    ) -> Result<VerifiedAssertion, WebAuthnError> {
        check_challenge(state, response)?;
        Ok(VerifiedAssertion {
            credential_id: stored.credential_id.clone(),
            new_sign_count: stored.sign_count + 1,
            updated_credential_data: None,
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

/// The `finish` request answering a `start` response (`{ ceremony_id, options }`)
/// with credential `cred_id`.
fn finish_body(start: Value, cred_id: &str) -> Value {
    json!({
        "ceremony_id": start["ceremony_id"],
        "response": { "id": cred_id, "challenge": start["options"]["challenge"] }
    })
}

/// Enroll credential `cred_id` using `cookie`'s session; `body` is sent to
/// `register/start` (the route must ignore it).
async fn enroll(app: &Router, cookie: &str, start_body: Value, cred_id: &str) {
    let start = post(app, "/passkey/register/start", Some(cookie), start_body).await;
    assert_eq!(start.status(), StatusCode::OK);
    let finish = post(
        app,
        "/passkey/register/finish",
        Some(cookie),
        finish_body(json_body(start).await, cred_id),
    )
    .await;
    assert_eq!(finish.status(), StatusCode::OK);
}

/// Run the passkey login ceremony for `cred_id`, returning the final response.
async fn passkey_login(app: &Router, email: Option<&str>, cred_id: &str) -> Response {
    let start = post(app, "/passkey/login/start", None, json!({ "email": email })).await;
    assert_eq!(start.status(), StatusCode::OK);
    post(
        app,
        "/passkey/login/finish",
        None,
        finish_body(json_body(start).await, cred_id),
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
        json!({ "ceremony_id": "anything", "response": { "id": "cred-evil" } }),
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

    // The credential was enrolled for the attacker's own account. It cannot
    // answer a login ceremony started for the victim...
    let as_victim = passkey_login(&app, Some(VICTIM), "cred-evil").await;
    assert_eq!(as_victim.status(), StatusCode::UNAUTHORIZED);

    // ...and where it does log in, it logs in as the attacker.
    let login = passkey_login(&app, Some(ATTACKER), "cred-evil").await;
    assert_eq!(login.status(), StatusCode::OK);
    assert_eq!(whoami_of(&app, &auth_cookie(&login)).await, ATTACKER);

    // A usernameless ceremony also resolves to the credential's real owner.
    let login = passkey_login(&app, None, "cred-evil").await;
    assert_eq!(login.status(), StatusCode::OK);
    assert_eq!(whoami_of(&app, &auth_cookie(&login)).await, ATTACKER);
}

#[tokio::test]
async fn a_ceremony_cannot_be_finished_from_another_account() {
    let app = app();
    let victim_cookie = signed_in(&app, VICTIM).await;
    let attacker_cookie = signed_in(&app, ATTACKER).await;

    // The victim starts enrolling; the attacker learns the whole start response.
    let start = post(
        &app,
        "/passkey/register/start",
        Some(&victim_cookie),
        json!({}),
    )
    .await;
    let finish = post(
        &app,
        "/passkey/register/finish",
        Some(&attacker_cookie),
        finish_body(json_body(start).await, "cred-evil"),
    )
    .await;
    assert_eq!(finish.status(), StatusCode::BAD_REQUEST);

    let login = passkey_login(&app, Some(VICTIM), "cred-evil").await;
    assert_eq!(login.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn another_accounts_credential_id_cannot_be_claimed() {
    let app = app();
    let victim_cookie = signed_in(&app, VICTIM).await;
    let attacker_cookie = signed_in(&app, ATTACKER).await;
    enroll(&app, &victim_cookie, json!({}), "cred-victim").await;

    // The attacker, in their own session, tries to register the same id.
    let start = post(
        &app,
        "/passkey/register/start",
        Some(&attacker_cookie),
        json!({}),
    )
    .await;
    let finish = post(
        &app,
        "/passkey/register/finish",
        Some(&attacker_cookie),
        finish_body(json_body(start).await, "cred-victim"),
    )
    .await;
    assert_eq!(finish.status(), StatusCode::CONFLICT);

    // The credential still logs in as the victim.
    let login = passkey_login(&app, Some(VICTIM), "cred-victim").await;
    assert_eq!(login.status(), StatusCode::OK);
    assert_eq!(whoami_of(&app, &auth_cookie(&login)).await, VICTIM);
}

// ---- Step-up: enrollment behind elevation ----------------------------------

/// No route handled the request: it fell through to the static-asset service,
/// which answers a `POST` with 405 (or 404).
fn is_unrouted(response: &Response) -> bool {
    matches!(
        response.status(),
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
    )
}

fn jwt_config(cookie: &str) -> JwtAuthConfig {
    JwtAuthConfig {
        jwt_cookie_name: cookie.to_string(),
        jwt_secret: Secret::new(format!("a-test-secret-that-is-long-enough-{cookie}")),
        token_ttl_in_seconds: 3600,
        audience: None,
        issuer: None,
    }
}

fn passkey_flow() -> PasskeyFlow<HashMapPasskeyCredentialStore, HashMapChallengeStore, MockVerifier>
{
    PasskeyFlow::new(
        HashMapPasskeyCredentialStore::new(),
        HashMapChallengeStore::new(),
        MockVerifier,
    )
}

/// A scheme where enrolling a passkey requires an elevated token. `passkeys_first`
/// picks the builder call order, which must not matter.
fn step_up_app(passkeys_first: bool) -> Router {
    let base = JwtScheme::new(
        HashMapUserStore::new(),
        jwt_config("jwt"),
        HashSetBannedTokenStore::new(),
        HashMapTokenEpochStore::new(),
    )
    .supports_registration();

    if passkeys_first {
        let scheme = base
            .supports_passkeys(passkey_flow())
            .supports_elevation(
                HashSetBannedTokenStore::new(),
                jwt_config("elevated_jwt"),
                |elevated| elevated.supports_passkey_enrollment(),
            )
            .build();
        auth_service(scheme, ".".to_string())
            .validated_router(Router::new().route("/whoami", get(whoami)))
            .into()
    } else {
        let scheme = base
            .supports_elevation(
                HashSetBannedTokenStore::new(),
                jwt_config("elevated_jwt"),
                |elevated| elevated.supports_passkey_enrollment(),
            )
            .supports_passkeys(passkey_flow())
            .build();
        auth_service(scheme, ".".to_string())
            .validated_router(Router::new().route("/whoami", get(whoami)))
            .into()
    }
}

/// Re-authenticate, returning a `Cookie` header value with both tokens.
async fn elevate(app: &Router, session: &str, email: &str) -> String {
    let response = post(
        app,
        "/elevate",
        Some(session),
        json!({ "email": email, "password": PASSWORD }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    format!("{session}; {}", auth_cookie(&response))
}

#[tokio::test]
async fn step_up_enrollment_requires_an_elevated_token() {
    for passkeys_first in [true, false] {
        let app = step_up_app(passkeys_first);
        let session = signed_in(&app, VICTIM).await;

        // A (possibly stolen) login session alone cannot enroll a passkey:
        // the login-level routes do not exist...
        let start = post(&app, "/passkey/register/start", Some(&session), json!({})).await;
        assert!(is_unrouted(&start), "got {}", start.status());
        // ...and the elevated ones refuse a plain session.
        let start = post(
            &app,
            "/elevated/passkey/register/start",
            Some(&session),
            json!({}),
        )
        .await;
        assert_eq!(start.status(), StatusCode::UNAUTHORIZED);

        // After re-authenticating, enrollment works and the passkey logs in.
        let cookies = elevate(&app, &session, VICTIM).await;
        let start = post(
            &app,
            "/elevated/passkey/register/start",
            Some(&cookies),
            json!({}),
        )
        .await;
        assert_eq!(start.status(), StatusCode::OK);
        let finish = post(
            &app,
            "/elevated/passkey/register/finish",
            Some(&cookies),
            finish_body(json_body(start).await, "cred-victim"),
        )
        .await;
        assert_eq!(finish.status(), StatusCode::OK);

        let login = passkey_login(&app, Some(VICTIM), "cred-victim").await;
        assert_eq!(login.status(), StatusCode::OK);
        assert_eq!(whoami_of(&app, &auth_cookie(&login)).await, VICTIM);
    }
}

#[tokio::test]
async fn step_up_enrollment_is_for_the_elevated_user() {
    let app = step_up_app(true);
    let victim_session = signed_in(&app, VICTIM).await;
    let attacker_session = signed_in(&app, ATTACKER).await;
    let victim = elevate(&app, &victim_session, VICTIM).await;
    let attacker = elevate(&app, &attacker_session, ATTACKER).await;

    // The victim starts; the attacker (elevated as themselves) cannot finish.
    let start = post(
        &app,
        "/elevated/passkey/register/start",
        Some(&victim),
        json!({}),
    )
    .await;
    let finish = post(
        &app,
        "/elevated/passkey/register/finish",
        Some(&attacker),
        finish_body(json_body(start).await, "cred-evil"),
    )
    .await;
    assert_eq!(finish.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn without_step_up_the_elevated_enrollment_routes_do_not_exist() {
    // `app()` has passkeys but no elevation: enrollment is login-gated.
    let app = app();
    let session = signed_in(&app, VICTIM).await;
    let start = post(
        &app,
        "/elevated/passkey/register/start",
        Some(&session),
        json!({}),
    )
    .await;
    assert!(is_unrouted(&start), "got {}", start.status());
}
