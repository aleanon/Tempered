use secrecy::Secret;
use tempered_adapters::http::{
    error::{AuthApiError, ErrorResponse},
    routes::TwoFactorAuthResponse,
};
use tempered_core::{Email, TwoFaAttemptId, TwoFaCodeStore, UserError, UserStoreError};
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

use crate::helpers::{TestApp, get_standard_test_user};

#[tokio::test]
async fn login_returns_200() {
    let app = TestApp::new().await;

    assert!(
        app.post_signup(&get_standard_test_user(false))
            .await
            .status()
            .as_u16()
            == 201
    );

    let body = serde_json::json!({
        "email": "test@example.com",
        "password": "password"
    });

    let response = app.login(&body).await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_206_when_2fa_enabled() {
    let app = TestApp::new().await;

    let body = get_standard_test_user(true);
    assert!(app.post_signup(&body).await.status().is_success());

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    let response = app.login(&body).await;

    assert_eq!(response.status().as_u16(), 206);

    let response = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Failed to parse response");

    assert_eq!(&response.message, "2FA required");

    let login_id = TwoFaAttemptId::parse(&response.attempt_id).expect("Invalid code");

    let email = Email::try_from(Secret::new(body["email"].as_str().unwrap().to_owned())).unwrap();
    let (login_attempt_id, _) = app
        .two_fa_code_store
        .get_login_attempt_id_and_two_fa_code(&email)
        .await
        .unwrap();
    assert_eq!(login_attempt_id, login_id)
}

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_enabled() {
    let app = TestApp::new().await;

    let body = get_standard_test_user(true);
    assert_eq!(app.post_signup(&body).await.status().as_u16(), 201);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    let response = app.login(&body).await;
    assert_eq!(response.status().as_u16(), 206);
    let response = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Failed to parse response");

    let login_attempt_id = TwoFaAttemptId::parse(&response.attempt_id).expect("Invalid code");

    let email_body = app
        .email_server
        .received_requests()
        .await
        .expect("Request recording disabled")
        .get(0)
        .expect("No email received")
        .body
        .clone();

    let email_json: serde_json::Value =
        serde_json::from_slice(&email_body).expect("Failed to parse email JSON");
    let code = email_json["TextBody"].as_str().expect("Missing content");

    let body = serde_json::json!({
        "email": body["email"].as_str().expect("Email was not a string"),
        "2FACode": code,
        "loginAttemptId": login_attempt_id.to_string(),
    });
    let response = app.verify_2fa(&body).await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_400_whith_invalid_email() {
    let app = TestApp::new().await;

    assert!(
        app.post_signup(&get_standard_test_user(false))
            .await
            .status()
            .is_success()
    );

    let body = serde_json::json!({
        "email": "test@example.c",
        "password": "password"
    });

    let response = app.login(&body).await;

    assert_eq!(response.status().as_u16(), 400);
    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Unable to parse Error response")
            .error,
        AuthApiError::InvalidInput(UserError::InvalidEmail.to_string()).to_string()
    )
}

#[tokio::test]
async fn should_return_400_whith_invalid_password() {
    let app = TestApp::new().await;

    assert!(
        app.post_signup(&get_standard_test_user(false))
            .await
            .status()
            .is_success()
    );

    let body = serde_json::json!({
        "email": "test@example.com",
        "password": "pass"
    });

    let response = app.login(&body).await;

    assert_eq!(response.status().as_u16(), 400);
    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Unable to parse Error response")
            .error,
        AuthApiError::InvalidInput(UserError::InvalidPassword.to_string()).to_string()
    )
}

#[tokio::test]
async fn should_return_401_with_wrong_password() {
    let app = TestApp::new().await;

    assert!(
        app.post_signup(&get_standard_test_user(false))
            .await
            .status()
            .is_success()
    );

    let body = serde_json::json!({
        "email": "test@example.com",
        "password": "wrongpassword",
    });

    let response = app.login(&body).await;

    assert_eq!(response.status().as_u16(), 401);
    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Unable to parse error response")
            .error,
        AuthApiError::AuthenticationError(UserStoreError::IncorrectPassword.to_string())
            .to_string()
    )
}

#[tokio::test]
async fn should_return_401_with_unregistered_email() {
    let app = TestApp::new().await;

    assert!(
        app.post_signup(&get_standard_test_user(false))
            .await
            .status()
            .is_success()
    );

    let body = serde_json::json!({
        "email": "unregistered@example.com",
        "password": "password",
    });

    let response = app.login(&body).await;

    assert_eq!(response.status().as_u16(), 401);
    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Unable to parse error response")
            .error,
        AuthApiError::UserNotFound.to_string()
    )
}

#[tokio::test]
async fn should_return_422_with_malformed_input() {
    let app = TestApp::new().await;

    assert!(
        app.post_signup(&get_standard_test_user(false))
            .await
            .status()
            .is_success()
    );

    let body = serde_json::json!({
        "emal": "test@example.com",
        "password": "password"
    });

    let response = app.login(&body).await;

    assert_eq!(response.status().as_u16(), 422);
}
