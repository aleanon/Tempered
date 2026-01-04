use crate::helpers::{JWT_ELEVATED_COOKIE_NAME, TestApp, get_standard_test_user};
use serde::Deserialize;

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
}

#[tokio::test]
async fn should_return_200_with_valid_elevated_token() {
    let app = TestApp::new().await;

    let body = get_standard_test_user(false);
    assert!(app.post_signup(&body).await.status().is_success());

    let response = app.login(&body).await;
    assert_eq!(response.status().as_u16(), 200);

    let response = app.post_elevate(&body).await;
    assert_eq!(response.status().as_u16(), 200);

    let token = app
        .get_token(JWT_ELEVATED_COOKIE_NAME)
        .expect("Missing elevated token in response");

    let response = app.verify_elevated_token(&token).await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_401_if_elevated_token_is_invalid() {
    let app = TestApp::new().await;

    let response = app.verify_elevated_token("invalid token").await;

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_401_if_regular_token_is_used() {
    let app = TestApp::new().await;

    let body = get_standard_test_user(false);
    assert!(app.post_signup(&body).await.status().is_success());

    let response = app.login(&body).await;
    assert_eq!(response.status().as_u16(), 200);

    let token = app.get_jwt_token().expect("Missing JWT token");

    let response = app.verify_elevated_token(&token).await;

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_401_if_elevated_token_is_banned() {
    let app = TestApp::new().await;

    let body = get_standard_test_user(false);
    assert!(app.post_signup(&body).await.status().is_success());

    assert_eq!(
        app.login(&body).await.status().as_u16(),
        200,
        "Failed to login"
    );

    let response = app.post_elevate(&body).await;
    assert_eq!(response.status().as_u16(), 200);

    let elevated_token = app
        .get_token(JWT_ELEVATED_COOKIE_NAME)
        .expect("Elevated token not found");

    assert!(app.logout().await.status().is_success());

    let response = app.verify_elevated_token(&elevated_token).await;

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

    let response = app.verify_elevated_token("").await;

    assert_eq!(response.status().as_u16(), 400);
}
