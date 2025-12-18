use tempered_adapters::auth::jwt::JWT_COOKIE_NAME;

use crate::helpers::{TestApp, get_standard_test_user};

#[tokio::test]
async fn should_return_200_if_jwt_cookie_is_valid() {
    let app = TestApp::new().await;

    let body = get_standard_test_user(false);
    app.post_signup(&body).await;
    app.login(&body).await;
    let token = app.get_jwt_token();

    let response = app.logout().await;

    assert_eq!(response.status().as_u16(), 200);

    let body = serde_json::json!({
        "token": token
    });

    let response = app.verify_token(&body).await;
    assert_eq!(response.status().as_u16(), 401)
}

#[tokio::test]
async fn logout_returns_400_if_jwt_cookie_is_missing() {
    let app = TestApp::new().await;

    let response = app.logout().await;

    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn should_return_400_if_logout_is_called_twice() {
    let app = TestApp::new().await;

    let body = get_standard_test_user(false);
    app.post_signup(&body).await;
    app.login(&body).await;

    let response = app.logout().await;

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(app.get_jwt_token(), None);

    let response = app.logout().await;

    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn logout_returns_401_if_invalid_token() {
    let app = TestApp::new().await;

    app.add_invalid_cookie(*JWT_COOKIE_NAME);

    let response = app.logout().await;

    assert_eq!(response.status().as_u16(), 401);
}
