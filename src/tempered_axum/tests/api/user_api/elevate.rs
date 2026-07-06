use crate::helpers::{TestApp, get_random_email, get_standard_test_user};

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
async fn should_return_401_with_valid_credentials_but_missing_auth_token() {
    let app = TestApp::new().await;

    let body = get_standard_test_user(false);
    assert!(app.post_signup(&body).await.status().is_success());

    let response = app.post_elevate(&body).await;
    assert_eq!(response.status().as_u16(), 401)
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
async fn should_return_403_when_elevating_with_another_users_credentials() {
    let app = TestApp::new().await;

    // A victim account whose password the attacker somehow knows.
    let victim = serde_json::json!({
        "email": get_random_email(),
        "password": "victim-password",
        "requires2FA": false
    });
    assert!(app.post_signup(&victim).await.status().is_success());

    // The attacker holds a valid session for their *own* account.
    let attacker = get_standard_test_user(false);
    assert!(app.post_signup(&attacker).await.status().is_success());
    assert!(app.login(&attacker).await.status().is_success());

    // Elevation with the victim's credentials must not yield an elevated
    // token scoped to the victim.
    let response = app.post_elevate(&victim).await;
    assert_eq!(response.status().as_u16(), 403);
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
