use reqwest::{Url, cookie::CookieStore};
use serde::Deserialize;

use crate::helpers::{TestApp, get_standard_test_user};

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
}

#[tokio::test]
async fn should_return_200_with_valid_token() {
    let app = TestApp::new().await;

    let body = get_standard_test_user(false);
    assert!(app.post_signup(&body).await.status().is_success());

    let response = app.login(&body).await;
    assert_eq!(response.status().as_u16(), 200);

    let cookie = app
        .cookie_jar
        .cookies(&Url::parse(&app.address).unwrap())
        .unwrap();

    let (_, token) = cookie.to_str().unwrap().split_once('=').unwrap();

    let body = serde_json::json!({
        "token": token
    });

    let response = app.verify_token(&body).await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_401_if_token_is_invalid() {
    let app = TestApp::new().await;

    let body = serde_json::json!({
        "token": "invalid token"
    });

    let response = app.verify_token(&body).await;

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_401_if_token_is_banned() {
    let app = TestApp::new().await;

    let body = get_standard_test_user(false);
    assert!(app.post_signup(&body).await.status().is_success());

    let response = app.login(&body).await;
    assert_eq!(response.status().as_u16(), 200);

    let token = app.get_jwt_token();

    assert!(app.logout().await.status().is_success());

    let body = serde_json::json!({
        "token": token
    });

    let response = app.verify_token(&body).await;

    assert_eq!(response.status().as_u16(), 401);
    let error_response = response
        .json::<ErrorResponse>()
        .await
        .expect("failed to parse error response");
    assert!(error_response.error.contains("token") || error_response.error.contains("banned"));
}

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let response = app.verify_token(&"").await;

    assert_eq!(response.status().as_u16(), 422);
}
