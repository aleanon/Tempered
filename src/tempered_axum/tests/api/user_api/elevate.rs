use crate::helpers::{TestApp, get_standard_test_user};

#[tokio::test]
async fn should_return_200_with_valid_credentials_and_logged_in_user() {
    let app = TestApp::new().await;

    let body = get_standard_test_user(false);
    assert!(app.post_signup(&body).await.status().is_success());
    assert!(app.login(&body).await.status().is_success());

    let response = app.post_elevate(&body).await;
    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_400_with_valid_credentials_but_missing_auth_token() {
    let app = TestApp::new().await;

    let body = get_standard_test_user(false);
    assert!(app.post_signup(&body).await.status().is_success());

    let response = app.post_elevate(&body).await;
    assert_eq!(response.status().as_u16(), 400)
}

#[tokio::test]
async fn should_return_401_with_valid_auth_token_but_invalid_credentials() {
    let app = TestApp::new().await;
    let body = get_standard_test_user(false);
    assert!(app.post_signup(&body).await.status().is_success());
    assert!(app.login(&body).await.status().is_success());

    let body = serde_json::json!({
       "email": body["email"],
       "password": "invalidpassword"
    });

    let response = app.post_elevate(&body).await;
    assert_eq!(response.status().as_u16(), 401)
}

#[tokio::test]
async fn should_return_422_with_malformed_input() {
    let app = TestApp::new().await;

    let body = get_standard_test_user(false);
    assert!(app.post_signup(&body).await.status().is_success());
    assert!(app.login(&body).await.status().is_success());

    let bodies = vec![
        serde_json::json!({
            "emal": body["email"], // Incorrect email field
            "password": body["password"]
        }),
        serde_json::json!({
            "email": body["email"],
            "pasword": body["password"] // Incorrect password field
        }),
        serde_json::json!({
            "email": body["email"], // Missing field
        }),
    ];

    for body in bodies {
        let response = app.post_elevate(&body).await;
        assert_eq!(response.status().as_u16(), 422)
    }
}
