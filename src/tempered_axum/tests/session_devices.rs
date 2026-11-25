//! A session scheme's device list: `/sessions` lists the user's sessions
//! (with the browser each was opened in), and ending one logs that device
//! out. In-memory stores and `tower::oneshot`.

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use serde_json::Value;
use tempered_adapters::authentication::session_scheme::{SessionConfig, SessionScheme};
use tempered_adapters::persistence::{HashMapSessionStore, HashMapUserStore};
use tempered_axum::auth_service::auth_service;
use tower::ServiceExt; // for `oneshot`

fn app() -> Router {
    let scheme = SessionScheme::new(
        HashMapUserStore::new(),
        HashMapSessionStore::new(),
        SessionConfig::new("session", 3600),
    )
    .supports_registration();
    auth_service(scheme, String::new()).into()
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

fn json(path: &str, body: &str) -> Request<Body> {
    Request::post(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn get(path: &str, cookie: &str, agent: &str) -> Request<Body> {
    // `/verify-token` is a POST; everything else here is a GET.
    let request = if path == "/verify-token" {
        Request::post(path)
    } else {
        Request::get(path)
    };
    request
        .header(header::COOKIE, cookie)
        .header(header::USER_AGENT, agent)
        .body(Body::empty())
        .unwrap()
}

async fn sign_up_and_log_in(app: &Router, email: &str) -> String {
    let credentials =
        format!(r#"{{"email":"{email}","password":"correct-horse","requires2FA":false}}"#);
    send(app, json("/signup", &credentials)).await;
    send(app, json("/login", &credentials)).await.1.unwrap()
}

async fn login(app: &Router, email: &str) -> String {
    let credentials = format!(r#"{{"email":"{email}","password":"correct-horse"}}"#);
    send(app, json("/login", &credentials)).await.1.unwrap()
}

#[tokio::test]
async fn a_user_sees_their_devices_and_can_log_one_out() {
    let app = app();
    let laptop = sign_up_and_log_in(&app, "user@example.com").await;
    let phone = login(&app, "user@example.com").await;
    // Each device makes a request, which records its browser.
    send(&app, get("/verify-token", &phone, "Phone Browser")).await;

    let (status, _, body) = send(&app, get("/sessions", &laptop, "Laptop Browser")).await;
    assert_eq!(status, StatusCode::OK);
    let sessions = body["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 2);
    let current: Vec<_> = sessions.iter().filter(|s| s["current"] == true).collect();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0]["userAgent"], "Laptop Browser");
    let phone_entry = sessions.iter().find(|s| s["current"] == false).unwrap();
    assert_eq!(phone_entry["userAgent"], "Phone Browser");
    // The handle is not the session id.
    let handle = phone_entry["handle"].as_str().unwrap();
    assert!(!phone.contains(handle));

    // Log the phone out from the laptop.
    let end = Request::delete(format!("/sessions/{handle}"))
        .header(header::COOKIE, &laptop)
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, end).await.0, StatusCode::OK);
    assert_eq!(
        send(&app, get("/verify-token", &phone, "Phone Browser"))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&app, get("/verify-token", &laptop, "Laptop Browser"))
            .await
            .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn nobody_can_end_another_users_session() {
    let app = app();
    let victim = sign_up_and_log_in(&app, "victim@example.com").await;
    let (_, _, body) = send(&app, get("/sessions", &victim, "Victim")).await;
    let handle = body["sessions"][0]["handle"].as_str().unwrap().to_string();

    let attacker = sign_up_and_log_in(&app, "attacker@example.com").await;
    let end = Request::delete(format!("/sessions/{handle}"))
        .header(header::COOKIE, &attacker)
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, end).await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        send(&app, get("/verify-token", &victim, "Victim")).await.0,
        StatusCode::OK
    );
}
