use serde::Deserialize;

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
}

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

        let error_response = response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse");
        assert!(error_response.error.contains("email") || error_response.error.contains("Invalid"));
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
        let error_response = response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize to error response");
        assert!(
            error_response.error.contains("password") || error_response.error.contains("Invalid")
        );
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
async fn signup_answers_a_taken_address_like_a_new_one() {
    let app = TestApp::new().await;

    let body = serde_json::json!({
        "email": "example@mail.com",
        "password": "passwordpassword",
        "requires2FA": false,
    });
    let first = app.post_signup(&body).await;
    assert_eq!(first.status().as_u16(), 201);
    let first: serde_json::Value = first.json().await.unwrap();

    // Same status and body: nothing says the address already had an account.
    let again = serde_json::json!({
        "email": "example@mail.com",
        "password": "a-different-password",
        "requires2FA": false,
    });
    let second = app.post_signup(&again).await;
    assert_eq!(second.status().as_u16(), 201);
    let second: serde_json::Value = second.json().await.unwrap();
    assert_eq!(first, second);

    // And the existing account is untouched: its password still works, the
    // second one does not.
    let login = app
        .login(&serde_json::json!({ "email": "example@mail.com", "password": "passwordpassword" }))
        .await;
    assert_eq!(login.status().as_u16(), 200);
    let login = app
        .login(
            &serde_json::json!({ "email": "example@mail.com", "password": "a-different-password" }),
        )
        .await;
    assert_eq!(login.status().as_u16(), 401);
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
