//! A framework-free adapter for the route table, to show it needs no web
//! framework: plain `http` types, a 30-line path matcher, and
//! `Endpoints::handle`. Everything a real adapter adds (a server, body
//! limits, static files) is beside the point here.
//!
//! The flows below run with no axum anywhere: login and cookie, the tiers
//! (login, verified, elevated), the JSON rules, logout.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Method, Request, StatusCode, header};
use secrecy::Secret;
use serde_json::{Value, json};
use tempered_adapters::auth_validation::local_jwt_validator::JwtAuthConfig;
use tempered_adapters::authentication::jwt_scheme::JwtScheme;
use tempered_adapters::endpoints::{
    EndpointRequest, EndpointResponse, Endpoints, PathOverrides, RouteSpec,
};
use tempered_adapters::persistence::{
    HashMapEmailVerificationTokenStore, HashMapTokenEpochStore, HashMapUserStore,
    HashSetBannedTokenStore,
};
use tempered_core::{Email, EmailClient};

// ---------------------------------------------------------------------------
// The adapter
// ---------------------------------------------------------------------------

struct App<S> {
    scheme: S,
    routes: Vec<RouteSpec>,
}

/// Match `path` against a `{name}` template, returning the parameters.
fn matches(template: &str, path: &str) -> Option<Vec<(String, String)>> {
    let (t, p): (Vec<_>, Vec<_>) = (template.split('/').collect(), path.split('/').collect());
    if t.len() != p.len() {
        return None;
    }
    let mut params = Vec::new();
    for (t, p) in t.iter().zip(&p) {
        match t.strip_prefix('{').and_then(|t| t.strip_suffix('}')) {
            Some(name) => params.push((name.to_string(), p.to_string())),
            None if t == p => {}
            None => return None,
        }
    }
    Some(params)
}

impl<S: Endpoints> App<S> {
    fn new(scheme: S) -> Self {
        let routes = scheme.routes(&PathOverrides::default());
        Self { scheme, routes }
    }

    async fn call(&self, request: Request<Bytes>) -> EndpointResponse {
        let (parts, body) = request.into_parts();
        let mut wrong_method = false;
        for spec in &self.routes {
            let Some(params) = matches(&spec.path, parts.uri.path()) else {
                continue;
            };
            if spec.method != parts.method {
                wrong_method = true;
                continue;
            }
            return self
                .scheme
                .handle(spec, EndpointRequest::new(parts, body, params))
                .await;
        }
        let status = if wrong_method {
            StatusCode::METHOD_NOT_ALLOWED
        } else {
            StatusCode::NOT_FOUND
        };
        http::Response::builder()
            .status(status)
            .body(String::new())
            .unwrap()
    }
}

// ---------------------------------------------------------------------------
// The scheme and helpers
// ---------------------------------------------------------------------------

/// Keeps every message (the verification token is the body).
#[derive(Clone, Default)]
struct Outbox(Arc<Mutex<Vec<String>>>);

impl Outbox {
    /// Mail `n` (from 0), waiting for it: signup mails go out after the
    /// response.
    async fn mail(&self, n: usize) -> String {
        for _ in 0..1000 {
            if let Some(mail) = self.0.lock().unwrap().get(n).cloned() {
                return mail;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        panic!("mail {n} was never sent");
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

fn app(outbox: &Outbox) -> App<impl Endpoints + use<>> {
    App::new(
        JwtScheme::new(
            HashMapUserStore::new(),
            config("jwt", "a-test-secret-that-is-long-enough"),
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .supports_registration()
        .supports_password_change()
        .supports_email_verification(HashMapEmailVerificationTokenStore::new(), outbox.clone())
        .supports_elevation(
            HashSetBannedTokenStore::new(),
            config("elevated_jwt", "an-elevated-test-secret-long-enough"),
            |e| e,
        ),
    )
}

fn post(path: &str, cookies: &[&str], body: Option<Value>) -> Request<Bytes> {
    let mut request = Request::builder().method(Method::POST).uri(path);
    if !cookies.is_empty() {
        request = request.header(header::COOKIE, cookies.join("; "));
    }
    match body {
        Some(body) => request
            .header(header::CONTENT_TYPE, "application/json")
            .body(Bytes::from(body.to_string())),
        None => request.body(Bytes::new()),
    }
    .unwrap()
}

/// The `name=value` part of the response's first `Set-Cookie`.
fn cookie(response: &EndpointResponse) -> String {
    let header = response.headers()[header::SET_COOKIE].to_str().unwrap();
    header.split(';').next().unwrap().to_string()
}

const EMAIL: &str = "user@example.com";
const PASSWORD: &str = "correct-horse-battery";

// ---------------------------------------------------------------------------
// The flows
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_route_table_runs_without_a_web_framework() {
    let outbox = Outbox::default();
    let app = app(&outbox);
    let credentials = json!({ "email": EMAIL, "password": PASSWORD, "requires2FA": false });

    let signup = app
        .call(post("/signup", &[], Some(credentials.clone())))
        .await;
    assert!(signup.status().is_success(), "{signup:?}");
    let login = app.call(post("/login", &[], Some(credentials))).await;
    assert_eq!(login.status(), StatusCode::OK);
    let session = cookie(&login);

    // Login tier.
    let anonymous = app.call(post("/verify-token", &[], None)).await;
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    let verify = app.call(post("/verify-token", &[&session], None)).await;
    assert_eq!(verify.status(), StatusCode::OK);

    // Verified tier: refused until the address is verified.
    let change = json!({ "new_password": "another-long-password" });
    let early = app
        .call(post("/change-password", &[&session], Some(change.clone())))
        .await;
    assert_eq!(early.status(), StatusCode::FORBIDDEN);
    let token = outbox.mail(0).await;
    let verified = app
        .call(post(
            "/verify-email",
            &[&session],
            Some(json!({ "token": token })),
        ))
        .await;
    assert_eq!(verified.status(), StatusCode::OK);

    // Elevated tier: reached through /elevate.
    let elevated_check = app
        .call(post("/elevated/verify-token", &[&session], None))
        .await;
    assert_eq!(elevated_check.status(), StatusCode::UNAUTHORIZED);
    let elevate = app
        .call(post(
            "/elevate",
            &[&session],
            Some(json!({ "email": EMAIL, "password": PASSWORD })),
        ))
        .await;
    assert_eq!(elevate.status(), StatusCode::OK, "{elevate:?}");
    let sudo = cookie(&elevate);
    let elevated_check = app
        .call(post("/elevated/verify-token", &[&sudo], None))
        .await;
    assert_eq!(elevated_check.status(), StatusCode::OK);

    let changed = app
        .call(post("/change-password", &[&session], Some(change)))
        .await;
    assert_eq!(changed.status(), StatusCode::OK);
}

#[tokio::test]
async fn json_rules_and_routing_errors_hold_without_a_framework() {
    let app = app(&Outbox::default());

    // No Content-Type: refused before parsing (part of the CSRF defence).
    let mut bare = post("/login", &[], None);
    *bare.body_mut() = Bytes::from(json!({ "email": EMAIL, "password": PASSWORD }).to_string());
    assert_eq!(
        app.call(bare).await.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    let shape = app
        .call(post("/login", &[], Some(json!({ "nope": 1 }))))
        .await;
    assert_eq!(shape.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body: Value = serde_json::from_str(shape.body()).unwrap();
    assert!(body["error"].is_string());

    let get = Request::builder()
        .method(Method::GET)
        .uri("/login")
        .body(Bytes::new())
        .unwrap();
    assert_eq!(app.call(get).await.status(), StatusCode::METHOD_NOT_ALLOWED);
    let missing = app.call(post("/nowhere", &[], None)).await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn logout_ends_the_session_without_a_framework() {
    let app = app(&Outbox::default());
    let credentials = json!({ "email": EMAIL, "password": PASSWORD, "requires2FA": false });
    app.call(post("/signup", &[], Some(credentials.clone())))
        .await;
    let session = cookie(&app.call(post("/login", &[], Some(credentials))).await);

    let logout = app.call(post("/logout", &[&session], None)).await;
    assert_eq!(logout.status(), StatusCode::OK);
    let after = app.call(post("/verify-token", &[&session], None)).await;
    assert_eq!(after.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn the_matcher_reads_path_parameters() {
    assert_eq!(
        matches("/oauth/{provider}/start", "/oauth/google/start"),
        Some(vec![("provider".to_string(), "google".to_string())])
    );
    assert_eq!(matches("/oauth/{provider}/start", "/oauth/google"), None);
    assert_eq!(matches("/login", "/login"), Some(vec![]));
}
