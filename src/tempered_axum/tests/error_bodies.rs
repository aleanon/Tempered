//! A store failure reaches the log, not the client: routes answer with the
//! classified message, never the store's own text (which can name tables,
//! constraints or hosts). In-memory stores and `tower::oneshot`.

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use secrecy::Secret;
use serde_json::json;
use tempered_adapters::auth_validation::local_jwt_validator::JwtAuthConfig;
use tempered_adapters::authentication::jwt_scheme::JwtScheme;
use tempered_adapters::email::MockEmailClient;
use tempered_adapters::persistence::{
    HashMapTokenEpochStore, HashMapUserStore, HashSetBannedTokenStore,
};
use tempered_axum::auth_service::auth_service;
use tempered_core::{
    Email, PasswordResetToken, PasswordResetTokenStore, PasswordResetTokenStoreError,
};
use tower::ServiceExt; // for `oneshot`

const STORE_DETAIL: &str = "relation \"password_reset_tokens\" on db-internal-7:5432";

/// A reset-token store whose every call fails with database-ish detail.
#[derive(Clone)]
struct BrokenResetStore;

fn broken() -> PasswordResetTokenStoreError {
    PasswordResetTokenStoreError::UnexpectedError(STORE_DETAIL.to_string().into())
}

#[async_trait::async_trait]
impl PasswordResetTokenStore for BrokenResetStore {
    async fn store_token(
        &self,
        _: PasswordResetToken,
        _: Email,
    ) -> Result<(), PasswordResetTokenStoreError> {
        Err(broken())
    }
    async fn get_email_for_token(
        &self,
        _: &PasswordResetToken,
    ) -> Result<Email, PasswordResetTokenStoreError> {
        Err(broken())
    }
    async fn delete_token(
        &self,
        _: &PasswordResetToken,
    ) -> Result<(), PasswordResetTokenStoreError> {
        Err(broken())
    }
    async fn consume_token(
        &self,
        _: &PasswordResetToken,
    ) -> Result<Email, PasswordResetTokenStoreError> {
        Err(broken())
    }
    async fn delete_all_for_user(&self, _: &Email) -> Result<(), PasswordResetTokenStoreError> {
        Err(broken())
    }
}

fn app() -> Router {
    let scheme = JwtScheme::new(
        HashMapUserStore::new(),
        JwtAuthConfig {
            jwt_cookie_name: "jwt".to_string(),
            jwt_secret: Secret::new("a-test-secret-that-is-long-enough".to_string()),
            token_ttl_in_seconds: 3600,
            audience: None,
            issuer: None,
        },
        HashSetBannedTokenStore::new(),
        HashMapTokenEpochStore::new(),
    )
    .supports_password_reset(BrokenResetStore, MockEmailClient::new());
    auth_service(scheme, "assets".to_string()).into()
}

#[tokio::test]
async fn a_failing_store_does_not_leak_into_the_reset_response() {
    let request = Request::builder()
        .method("POST")
        .uri("/password-reset/complete")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "reset_token": PasswordResetToken::new().to_string(),
                "new_password": "a-long-new-password",
            })
            .to_string(),
        ))
        .unwrap();

    let response = app().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(!body.contains("db-internal"), "leaked: {body}");
    assert!(body.contains("Internal error"), "body: {body}");
}

/// A 2FA-code store whose every call fails, as Redis does when it is down.
#[derive(Clone)]
struct Broken2FaStore;

fn broken_2fa() -> tempered_core::TwoFaCodeStoreError {
    tempered_core::TwoFaCodeStoreError::UnexpectedError(STORE_DETAIL.to_string().into())
}

#[async_trait::async_trait]
impl tempered_core::TwoFaCodeStore for Broken2FaStore {
    async fn store_code(
        &self,
        _: Email,
        _: tempered_core::TwoFaAttemptId,
        _: tempered_core::TwoFaCode,
    ) -> Result<(), tempered_core::TwoFaCodeStoreError> {
        Err(broken_2fa())
    }

    async fn redeem_code(
        &self,
        _: &Email,
        _: &tempered_core::TwoFaAttemptId,
        _: &tempered_core::TwoFaCode,
    ) -> Result<(), tempered_core::TwoFaCodeStoreError> {
        Err(broken_2fa())
    }

    async fn get_login_attempt_id_and_two_fa_code(
        &self,
        _: &Email,
    ) -> Result<
        (tempered_core::TwoFaAttemptId, tempered_core::TwoFaCode),
        tempered_core::TwoFaCodeStoreError,
    > {
        Err(broken_2fa())
    }

    async fn delete(&self, _: &Email) -> Result<(), tempered_core::TwoFaCodeStoreError> {
        Err(broken_2fa())
    }
}

/// A 2FA store outage is the server's fault. Answering "invalid or expired
/// code" would send the user to retype a code that was never checked.
#[tokio::test]
async fn a_failing_2fa_store_is_a_server_error_not_a_wrong_code() {
    let scheme = JwtScheme::new(
        HashMapUserStore::new(),
        JwtAuthConfig {
            jwt_cookie_name: "jwt".to_string(),
            jwt_secret: Secret::new("a-test-secret-that-is-long-enough".to_string()),
            token_ttl_in_seconds: 3600,
            audience: None,
            issuer: None,
        },
        HashSetBannedTokenStore::new(),
        HashMapTokenEpochStore::new(),
    )
    .supports_registration()
    .supports_2fa(Broken2FaStore, MockEmailClient::new());
    let app: Router = auth_service(scheme, "assets".to_string()).into();
    let post = |uri: &str, body: serde_json::Value| {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let credentials =
        json!({ "email": "a@example.com", "password": "a-long-password", "requires2FA": true });
    app.clone()
        .oneshot(post("/signup", credentials.clone()))
        .await
        .unwrap();

    for (uri, body) in [
        ("/login", credentials),
        (
            "/verify-2fa",
            json!({
                "email": "a@example.com",
                "loginAttemptId": tempered_core::TwoFaAttemptId::default().to_string(),
                "2FACode": "123456",
            }),
        ),
    ] {
        let response = app.clone().oneshot(post(uri, body)).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "{uri}"
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(!body.contains("db-internal"), "leaked: {body}");
    }
}
