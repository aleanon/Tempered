use secrecy::Secret;
use serde::Deserialize;
use tempered_adapters::auth_validation::local_jwt_validator::{JwtAuthConfig, validate_auth_token};
use tempered_core::TwoFaAttemptId;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

use crate::helpers::{JWT_COOKIE_NAME, JWT_SECRET, TestApp, get_standard_test_user};

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Deserialize)]
struct TwoFactorAuthResponse {
    status: String,
    message: String,
    #[serde(rename = "loginAttemptId")]
    login_attempt_id: String,
}

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
        TwoFaAttemptId::parse(&two_fa_response.login_attempt_id).expect("Invalid attempt Id");
    let verify_2fa_request = app
        .get_verify_two_fa_request(email, two_fa_attempt_id)
        .await;

    let jwt_config = JwtAuthConfig {
        jwt_cookie_name: JWT_COOKIE_NAME.to_string(),
        jwt_secret: Secret::new(JWT_SECRET.to_string()),
        token_ttl_in_seconds: 3600,
    };

    let response = app.verify_2fa(&verify_2fa_request).await;
    let token = app.get_jwt_token().expect("No jwt token stored");
    validate_auth_token(&token, &app.banned_token_store, &jwt_config)
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
        TwoFaAttemptId::parse(&two_fa_response.login_attempt_id).expect("Invalid attempt Id");
    let verify_2fa_body = app
        .get_verify_two_fa_request(email, two_fa_attempt_id)
        .await;

    let body = serde_json::json!({
        "email": verify_2fa_body["email"],
        "loginAttemptId": format!("{}invalid", verify_2fa_body["loginAttemptId"].as_str().unwrap()),
        "2FACode": verify_2fa_body["2FACode"],
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
        TwoFaAttemptId::parse(&two_fa_response.login_attempt_id).expect("Invalid attempt Id");

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
        "error"
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
        TwoFaAttemptId::parse(&two_fa_response.login_attempt_id).expect("Invalid attempt Id");

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
        TwoFaAttemptId::parse(&two_fa_response.login_attempt_id).expect("Invalid attempt Id");

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
