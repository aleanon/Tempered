use auth_adapters::http::error::{AuthApiError, ErrorResponse};
use auth_core::UserError;

use crate::helpers::{TestApp, get_random_email};

#[tokio::test]
async fn signup_should_return_201_with_valid_input() {
    let app = TestApp::new().await;

    let body = serde_json::json!({
        "email": "test@example.com",
        "password": "passwordpassword",
        "requires2FA": false,
    });

    let response = app.post_signup(&body).await;

    assert_eq!(response.status().as_u16(), 201);
}

#[tokio::test]
async fn should_return_400_if_invalid_email() {
    let app = TestApp::new().await;

    let emails = vec!["invalid_email", "test@example.c"];

    for email in emails {
        let body = serde_json::json!({
            "email": email,
            "password": "password",
            "requires2FA": false,
        });

        let response = app.post_signup(&body).await;
        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for email: {:?}",
            email
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            AuthApiError::InvalidInput(UserError::InvalidEmail.to_string()).to_string()
        );
    }
}

#[tokio::test]
async fn signup_should_return_400_if_invalid_password() {
    let app = TestApp::new().await;

    let passwords = vec!["short"];

    for password in passwords {
        let body = serde_json::json!({
            "email": "test@example.com",
            "password": password,
            "requires2FA": false,
        });

        let response = app.post_signup(&body).await;

        assert_eq!(response.status().as_u16(), 400);
        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize to error response")
                .error,
            AuthApiError::InvalidInput(UserError::InvalidPassword.to_string()).to_string()
        )
    }

    let body = serde_json::json!({
        "email": "test@example.com",
        "password": "short",
        "requires2FA": false,
    });

    let response = app.post_signup(&body).await;

    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn signup_should_return_409_if_email_already_exists() {
    let app = TestApp::new().await;

    let body = serde_json::json!({
        "email": "example@mail.com",
        "password": "passwordpassword",
        "requires2FA": false,
    });

    let response = app.post_signup(&body).await;

    assert_eq!(response.status().as_u16(), 201);

    let response = app.post_signup(&body).await;

    assert_eq!(response.status().as_u16(), 409);
    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        AuthApiError::UserAlreadyExists.to_string()
    );
}

#[tokio::test]
async fn signup_returns_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = vec![
        serde_json::json!({
            "password": "password123",
            "requires2FA": false,
        }),
        serde_json::json!({
            "email": random_email,
            "password": "password123",
        }),
        serde_json::json!({
            "email": random_email,
            "password": 21321989,
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "password": false,
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "password": "password123",
            "requires2FA": 10
        }),
        serde_json::json!({
            "email": 19299190,
            "password": "password123",
            "requires2FA": true
        }),
    ];

    for body in test_cases {
        let response = app.post_signup(&body).await;
        assert_eq!(response.status().as_u16(), 422);
    }
}
