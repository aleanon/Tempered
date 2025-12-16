use auth_adapters::{
    auth,
    http::{
        error::{AuthApiError, ErrorResponse},
        routes::{TwoFactorAuthResponse, Verify2FARequest},
    },
};
use auth_core::TwoFaAttemptId;

use secrecy::ExposeSecret;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

use crate::helpers::{TestApp, get_standard_test_user};

#[tokio::test]
async fn should_return_200_if_correct_code() {
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

    let two_fa_response = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Failed to get two factor response");

    let email = body["email"]
        .as_str()
        .expect("Email was not of type String");
    let two_fa_attempt_id =
        TwoFaAttemptId::parse(&two_fa_response.attempt_id).expect("Invalid attempt Id");
    let verify_2fa_request = app
        .get_verify_two_fa_request(email, two_fa_attempt_id)
        .await;

    let response = app.verify_2fa(&verify_2fa_request).await;
    let token = app.get_jwt_token().expect("No jwt token stored");
    let banned_token_store = app.banned_token_store.read().await;
    auth::validate_auth_token(&token, &*banned_token_store)
        .await
        .expect("Invalid auth token");

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_400_with_invalid_input() {
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

    let two_fa_response = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Failed to get two factor response");

    let email = body["email"]
        .as_str()
        .expect("Email was not of type String");
    let two_fa_attempt_id =
        TwoFaAttemptId::parse(&two_fa_response.attempt_id).expect("Invalid attempt Id");
    let body = app
        .get_verify_two_fa_request(email, two_fa_attempt_id)
        .await;

    let to_fa_request = serde_json::from_value::<Verify2FARequest>(body)
        .expect("Failed to parse two factor auth request");

    let body = serde_json::json!({
        "email": to_fa_request.email.expose_secret(),
        "loginAttemptId": format!("{}invalid", to_fa_request.login_attempt_id),
        "2FACode": to_fa_request.two_factor_code,
    });

    let response = app.verify_2fa(&body).await;
    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn should_return_401_with_outdated_login_attempt_id() {
    let app = TestApp::new().await;

    let body = get_standard_test_user(true);
    assert!(app.post_signup(&body).await.status().is_success());

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&app.email_server)
        .await;

    let response = app.login(&body).await;
    assert_eq!(response.status().as_u16(), 206);

    let two_fa_response = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Failed to get two factor response");

    let email = body["email"]
        .as_str()
        .expect("Email was not of type String");
    let two_fa_attempt_id =
        TwoFaAttemptId::parse(&two_fa_response.attempt_id).expect("Invalid attempt Id");

    assert!(app.login(&body).await.status().as_u16() == 206);

    let body = app
        .get_verify_two_fa_request(email, two_fa_attempt_id)
        .await;

    let response = app.verify_2fa(&body).await;

    assert_eq!(response.status().as_u16(), 401);
    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Failed to parse error response")
            .error,
        AuthApiError::InvalidLoginAttemptId.to_string()
    )
}

#[tokio::test]
async fn should_return_401_if_same_code_twice() {
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

    let two_fa_response = &response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Failed to get two factor response");

    let email = body["email"]
        .as_str()
        .expect("Email was not of type String");
    let two_fa_attempt_id =
        TwoFaAttemptId::parse(&two_fa_response.attempt_id).expect("Invalid attempt Id");

    let body = app
        .get_verify_two_fa_request(email, two_fa_attempt_id)
        .await;

    assert_eq!(app.verify_2fa(&body).await.status().as_u16(), 200);
    assert_eq!(app.verify_2fa(&body).await.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_422_when_malformed_input() {
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

    let two_fa_response = &response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Failed to get two factor response");

    let email = body["email"]
        .as_str()
        .expect("Email was not of type String");
    let two_fa_attempt_id =
        TwoFaAttemptId::parse(&two_fa_response.attempt_id).expect("Invalid attempt Id");

    let body = app
        .get_verify_two_fa_request(email, two_fa_attempt_id)
        .await;

    let body = serde_json::json!({
        "email": body["email"].as_str().unwrap(),
        "loginAttemptI": body["loginAttemptId"].as_str().unwrap(), // Missing the d in Id
        "2FACode": body["2FACode"].as_str().unwrap()
    });

    let response = app.verify_2fa(&body).await;

    assert_eq!(response.status().as_u16(), 422);
}
