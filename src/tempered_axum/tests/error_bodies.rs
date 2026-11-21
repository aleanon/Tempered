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
    PasswordResetTokenStoreError::UnexpectedError(STORE_DETAIL.to_string())
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
