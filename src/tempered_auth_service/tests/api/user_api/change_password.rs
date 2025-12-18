use tempered_adapters::auth::jwt::JWT_ELEVATED_COOKIE_NAME;

use crate::helpers::{TestApp, get_standard_test_user};

#[tokio::test]
async fn should_return_200_with_valid_request_and_elevated_auth() {
    let app = TestApp::new().await;

    let body = get_standard_test_user(false);
    assert_eq!(
        app.post_signup(&body).await.status().as_u16(),
        201,
        "Failed to signup"
    );
    assert_eq!(
        app.login(&body).await.status().as_u16(),
        200,
        "Failed to login"
    );
    assert_eq!(app.post_elevate(&body).await.status().as_u16(), 200);

    let new_password = serde_json::json!({
        "new_password": "newpassword123"
    });

    let response = app.post_change_password(&new_password).await;
    assert_eq!(response.status().as_u16(), 200);

    app.logout().await;
    assert_eq!(app.login(&body).await.status().as_u16(), 401);

    let new_body = serde_json::json!({
        "email": body["email"].as_str().unwrap(),
        "password": "newpassword123"
    });

    let response = app.login(&new_body).await;
    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_400_with_missing_token() {
    let app = TestApp::new().await;

    let body = serde_json::json!({
        "new_password": "newpassword123"
    });

    let response = app.post_change_password(&body).await;
    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn should_return_401_with_invalid_token() {
    let app = TestApp::new().await;

    // Add an invalid elevated token
    app.add_invalid_cookie(*JWT_ELEVATED_COOKIE_NAME);

    let body = serde_json::json!({
        "new_password": "newpassword123"
    });

    let response = app.post_change_password(&body).await;
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_400_with_invalid_password() {
    let app = TestApp::new().await;

    let user_body = get_standard_test_user(false);
    assert_eq!(
        app.post_signup(&user_body).await.status().as_u16(),
        201,
        "Failed to signup"
    );
    assert_eq!(
        app.login(&user_body).await.status().as_u16(),
        200,
        "Failed to login"
    );
    assert_eq!(app.post_elevate(&user_body).await.status().as_u16(), 200);

    let body = serde_json::json!({
        "new_password": "123"
    });

    let response = app.post_change_password(&body).await;
    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn should_return_422_with_missing_password() {
    let app = TestApp::new().await;

    let user_body = get_standard_test_user(false);
    assert_eq!(
        app.post_signup(&user_body).await.status().as_u16(),
        201,
        "Failed to signup"
    );
    assert_eq!(
        app.login(&user_body).await.status().as_u16(),
        200,
        "Failed to login"
    );
    assert_eq!(app.post_elevate(&user_body).await.status().as_u16(), 200);

    // Test with empty body
    let body = serde_json::json!({});

    let response = app.post_change_password(&body).await;
    assert_eq!(response.status().as_u16(), 422);
}

#[tokio::test]
async fn should_return_422_with_invalid_json() {
    let app = TestApp::new().await;

    let user_body = get_standard_test_user(false);
    assert_eq!(
        app.post_signup(&user_body).await.status().as_u16(),
        201,
        "Failed to signup"
    );
    assert_eq!(
        app.login(&user_body).await.status().as_u16(),
        200,
        "Failed to login"
    );
    assert_eq!(app.post_elevate(&user_body).await.status().as_u16(), 200);

    // Test with password as wrong type
    let body = serde_json::json!({
        "password": 12345
    });

    let response = app.post_change_password(&body).await;
    assert_eq!(response.status().as_u16(), 422);
}
