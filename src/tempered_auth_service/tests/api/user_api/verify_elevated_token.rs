use tempered_adapters::{
    auth_validation::{TokenAuthError, jwt::JWT_ELEVATED_COOKIE_NAME},
    http::error::{AuthApiError, ErrorResponse},
};

use crate::helpers::{TestApp, get_standard_test_user};

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
        .get_token(*JWT_ELEVATED_COOKIE_NAME)
        .expect("Missing elevated token in response");

    let body = serde_json::json!({
        "token": token
    });

    let response = app.verify_elevated_token(&body).await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_401_if_elevated_token_is_invalid() {
    let app = TestApp::new().await;

    let body = serde_json::json!({
        "token": "invalid token"
    });

    let response = app.verify_elevated_token(&body).await;

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_401_if_regular_token_is_used() {
    let app = TestApp::new().await;

    let body = get_standard_test_user(false);
    assert!(app.post_signup(&body).await.status().is_success());

    let response = app.login(&body).await;
    assert_eq!(response.status().as_u16(), 200);

    let token = app.get_jwt_token();

    let body = serde_json::json!({
        "token": token
    });

    let response = app.verify_elevated_token(&body).await;

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
        .get_token(*JWT_ELEVATED_COOKIE_NAME)
        .expect("Elevated token not found");

    assert!(app.logout().await.status().is_success());

    let body = serde_json::json!({
        "token": elevated_token
    });

    let response = app.verify_elevated_token(&body).await;

    assert_eq!(response.status().as_u16(), 401);
    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("failed to parse error response")
            .error,
        AuthApiError::AuthenticationError(TokenAuthError::TokenIsBanned.to_string()).to_string()
    )
}

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let response = app.verify_elevated_token(&"").await;

    assert_eq!(response.status().as_u16(), 422);
}
