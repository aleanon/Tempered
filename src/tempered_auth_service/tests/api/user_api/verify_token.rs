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

    let response = app.verify_token(token).await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_401_if_token_is_invalid() {
    let app = TestApp::new().await;

    let response = app.verify_token("invalid token").await;

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_401_if_token_is_banned() {
    let app = TestApp::new().await;

    let body = get_standard_test_user(false);
    assert!(app.post_signup(&body).await.status().is_success());

    let response = app.login(&body).await;
    assert_eq!(response.status().as_u16(), 200);

    let token = app.get_jwt_token().expect("Missing JWT token");

    assert!(app.logout().await.status().is_success());

    let response = app.verify_token(&token).await;

    assert_eq!(response.status().as_u16(), 401);
    let error_response = response
        .json::<ErrorResponse>()
        .await
        .expect("failed to parse error response");
    assert!(error_response.error.contains("token") || error_response.error.contains("banned"));
}

#[tokio::test]
async fn should_return_400_if_missing_token() {
    let app = TestApp::new().await;

    let response = app.verify_token("").await;

    assert_eq!(response.status().as_u16(), 400);
}
