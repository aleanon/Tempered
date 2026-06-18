//! Opaque server-side session authentication scheme.
//!
//! The stateful counterpart to [`JwtScheme`](crate::authentication::jwt_scheme::JwtScheme):
//! login verifies the password via the [`UserStore`], creates a server-side
//! session in a [`SessionStore`], and returns the random [`SessionId`] in an
//! HttpOnly cookie. Because the session lives server-side, logout (or any
//! `delete_session`) revokes it instantly — no ban-list needed.
//!
//! It satisfies [`HttpAuthenticationScheme`] with cookie delivery, so the
//! existing `auth_service` login / logout / verify-token routes work unchanged.

use async_trait::async_trait;
use axum_extra::extract::CookieJar;
use secrecy::Secret;
use serde::Deserialize;
use tempered_core::{
    AuthRequest, AuthValidator, AuthenticationScheme, Email, HttpAuthenticationScheme,
    HttpResponseBuilderExt, IntoStatusMessage, LoginOutcome, Password, ResponseBuilder,
    ResponseBuilderError, SessionId, SessionStore, SessionStoreError, SupportsTokenRevocation,
    UserError, UserStore, UserStoreError,
};
use thiserror::Error;

// ============================================================================
// Configuration
// ============================================================================

#[derive(Clone)]
pub struct SessionConfig {
    pub cookie_name: String,
    pub ttl_in_seconds: u64,
}

// ============================================================================
// Session Scheme
// ============================================================================

#[derive(Clone)]
pub struct SessionScheme<U, S> {
    user_store: U,
    session_store: S,
    config: SessionConfig,
    validator: SessionValidator<S>,
}

impl<U, S> SessionScheme<U, S>
where
    U: UserStore + Clone,
    S: SessionStore + Clone,
{
    pub fn new(user_store: U, session_store: S, config: SessionConfig) -> Self {
        let validator = SessionValidator::new(session_store.clone(), config.clone());
        Self {
            user_store,
            session_store,
            config,
            validator,
        }
    }
}

// ============================================================================
// Domain / wire types
// ============================================================================

/// Opaque session token delivered to the client (wraps a `SessionId`).
#[derive(Clone, Debug)]
pub struct SessionToken(pub SessionId);

/// Credentials accepted by the session login endpoint.
#[derive(Debug, Deserialize)]
pub struct SessionCredentials {
    pub email: Secret<String>,
    pub password: Secret<String>,
}

// ============================================================================
// Core trait: AuthenticationScheme
// ============================================================================

#[async_trait]
impl<U, S> AuthenticationScheme for SessionScheme<U, S>
where
    U: UserStore + Clone + 'static,
    S: SessionStore + Clone + Send + Sync + 'static,
{
    type Token = SessionToken;
    type LogoutOutput = String;
    type Validator = SessionValidator<S>;
    type Credentials = SessionCredentials;
    type AuthError = SessionAuthError;

    #[tracing::instrument(name = "SessionScheme::login", skip(self, credentials))]
    async fn login(
        &self,
        credentials: Self::Credentials,
    ) -> Result<LoginOutcome<Self::Token>, Self::AuthError> {
        let email = Email::try_from(credentials.email)?;
        let password = Password::try_from(credentials.password)?;

        // This scheme does not implement 2FA; a validated user (with or without
        // the 2FA flag) is treated as an immediate session grant.
        let validated_user = self.user_store.authenticate_user(&email, &password).await?;
        let session_email = validated_user.email().clone();

        let id = SessionId::new();
        self.session_store
            .create_session(id.clone(), session_email)
            .await?;

        Ok(LoginOutcome::Success(SessionToken(id)))
    }

    async fn logout(&self, token: &Self::Token) -> Result<Self::LogoutOutput, Self::AuthError> {
        self.session_store.delete_session(&token.0).await?;
        Ok(self.config.cookie_name.clone())
    }

    fn validator(&self) -> &Self::Validator {
        &self.validator
    }
}

// ============================================================================
// HTTP delivery (cookie-based)
// ============================================================================

fn build_session_cookie(value: &str, name: &str, ttl_seconds: u64) -> String {
    format!(
        "{}={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
        name, value, ttl_seconds
    )
}

impl<U, S> HttpAuthenticationScheme for SessionScheme<U, S>
where
    U: UserStore + Clone + 'static,
    S: SessionStore + Clone + Send + Sync + 'static,
{
    fn create_login_response<RB: ResponseBuilder>(
        &self,
        builder: RB,
        outcome: LoginOutcome<Self::Token>,
    ) -> Result<RB::Response, ResponseBuilderError> {
        match outcome {
            LoginOutcome::Success(token) => {
                let cookie = build_session_cookie(
                    &token.0.to_string(),
                    &self.config.cookie_name,
                    self.config.ttl_in_seconds,
                );
                builder
                    .status(200)
                    .cookie(&cookie)
                    .json_body(serde_json::json!({
                        "status": "success",
                        "message": "Login successful"
                    }))
                    .build()
            }
            LoginOutcome::Requires2Fa {
                email: _,
                attempt_id,
            } => builder
                .status(206)
                .json_body(serde_json::json!({
                    "status": "requires_2fa",
                    "loginAttemptId": attempt_id.to_string()
                }))
                .build(),
        }
    }

    fn create_logout_response<RB: ResponseBuilder>(
        &self,
        builder: RB,
        cookie_name: Option<String>,
    ) -> Result<RB::Response, ResponseBuilderError> {
        let cookie_name = cookie_name.unwrap_or_else(|| self.config.cookie_name.clone());
        let clear_cookie = format!(
            "{}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
            cookie_name
        );
        builder
            .status(200)
            .cookie(&clear_cookie)
            .json_body(serde_json::json!({ "message": "Logged out successfully" }))
            .build()
    }

    fn extract_token_from_request<Req: AuthRequest>(&self, req: &Req) -> Option<Self::Token> {
        req.cookie(&self.config.cookie_name)
            .and_then(SessionId::parse)
            .map(SessionToken)
    }
}

// ============================================================================
// Token revocation (logout = delete the server-side session)
// ============================================================================

#[async_trait]
impl<U, S> SupportsTokenRevocation for SessionScheme<U, S>
where
    U: UserStore + Clone + 'static,
    S: SessionStore + Clone + Send + Sync + 'static,
{
    type RevocationError = SessionAuthError;

    async fn revoke_token(&self, token: &Self::Token) -> Result<(), Self::RevocationError> {
        self.session_store.delete_session(&token.0).await?;
        Ok(())
    }
}

// ============================================================================
// Validator
// ============================================================================

/// Claims extracted from a valid session (currently just the user's email).
#[derive(Clone, Debug)]
pub struct SessionClaims {
    pub email: Email,
}

#[derive(Clone)]
pub struct SessionValidator<S> {
    session_store: S,
    cookie_name: String,
}

impl<S> SessionValidator<S> {
    pub fn new(session_store: S, config: SessionConfig) -> Self {
        Self {
            session_store,
            cookie_name: config.cookie_name,
        }
    }
}

#[async_trait]
impl<S> AuthValidator for SessionValidator<S>
where
    S: SessionStore + Clone + 'static,
{
    type Claims = SessionClaims;
    type RequestParts = http::request::Parts;
    type Error = SessionAuthError;

    async fn validate(&self, parts: &Self::RequestParts) -> Result<Self::Claims, Self::Error> {
        let jar = CookieJar::from_headers(&parts.headers);

        let raw = jar
            .get(&self.cookie_name)
            .map(|c| c.value().to_string())
            .filter(|v| !v.is_empty())
            .ok_or(SessionAuthError::MissingSession)?;

        let id = SessionId::parse(&raw).ok_or(SessionAuthError::InvalidSession)?;

        let email = self.session_store.get_session(&id).await?;

        // Best-effort sliding expiry; failure to touch should not reject a
        // request that just validated successfully.
        let _ = self.session_store.touch_session(&id).await;

        Ok(SessionClaims { email })
    }
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, Error)]
pub enum SessionAuthError {
    #[error("User error: {0}")]
    UserError(#[from] UserError),

    #[error("User store error: {0}")]
    UserStoreError(#[from] UserStoreError),

    #[error("Session store error: {0}")]
    SessionStoreError(#[from] SessionStoreError),

    #[error("Missing session cookie")]
    MissingSession,

    #[error("Invalid session")]
    InvalidSession,
}

impl IntoStatusMessage for SessionAuthError {
    fn into_status_message(self) -> (http::StatusCode, String) {
        match self {
            SessionAuthError::UserError(e) => (http::StatusCode::BAD_REQUEST, e.to_string()),

            SessionAuthError::UserStoreError(UserStoreError::UserNotFound) => {
                (http::StatusCode::UNAUTHORIZED, "User not found".to_string())
            }
            SessionAuthError::UserStoreError(UserStoreError::IncorrectPassword) => (
                http::StatusCode::UNAUTHORIZED,
                "Incorrect password".to_string(),
            ),
            SessionAuthError::UserStoreError(e) => (
                http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("User store error: {}", e),
            ),

            SessionAuthError::MissingSession => {
                (http::StatusCode::UNAUTHORIZED, "Missing session".to_string())
            }
            SessionAuthError::InvalidSession => {
                (http::StatusCode::UNAUTHORIZED, "Invalid session".to_string())
            }
            SessionAuthError::SessionStoreError(SessionStoreError::SessionNotFound) => (
                http::StatusCode::UNAUTHORIZED,
                "Session not found or expired".to_string(),
            ),
            SessionAuthError::SessionStoreError(SessionStoreError::UnexpectedError(m)) => {
                (http::StatusCode::INTERNAL_SERVER_ERROR, m)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::hashmap_session_store::HashMapSessionStore;
    use crate::persistence::hashmap_user_store::HashMapUserStore;
    use tempered_core::User;

    fn config() -> SessionConfig {
        SessionConfig {
            cookie_name: "session".to_string(),
            ttl_in_seconds: 3600,
        }
    }

    async fn scheme_with_user(
        email: &str,
        password: &str,
    ) -> SessionScheme<HashMapUserStore, HashMapSessionStore> {
        let user_store = HashMapUserStore::new();
        let user = User::parse(
            Secret::new(email.to_string()),
            Secret::new(password.to_string()),
            false,
        )
        .unwrap();
        user_store.add_user(user).await.unwrap();
        SessionScheme::new(user_store, HashMapSessionStore::new(), config())
    }

    #[tokio::test]
    async fn login_creates_session_and_validator_accepts_it() {
        let scheme = scheme_with_user("user@example.com", "passwordpassword").await;

        let outcome = scheme
            .login(SessionCredentials {
                email: Secret::new("user@example.com".to_string()),
                password: Secret::new("passwordpassword".to_string()),
            })
            .await
            .unwrap();

        let token = match outcome {
            LoginOutcome::Success(t) => t,
            _ => panic!("expected immediate success"),
        };

        // Build request parts carrying the session cookie and validate.
        let parts = parts_with_cookie("session", &token.0.to_string());
        let claims = scheme.validator().validate(&parts).await.unwrap();
        assert_eq!(claims.email, Email::try_from(Secret::new("user@example.com".to_string())).unwrap());
    }

    #[tokio::test]
    async fn logout_revokes_session_immediately() {
        let scheme = scheme_with_user("user@example.com", "passwordpassword").await;
        let outcome = scheme
            .login(SessionCredentials {
                email: Secret::new("user@example.com".to_string()),
                password: Secret::new("passwordpassword".to_string()),
            })
            .await
            .unwrap();
        let token = match outcome {
            LoginOutcome::Success(t) => t,
            _ => panic!("expected success"),
        };

        scheme.logout(&token).await.unwrap();

        let parts = parts_with_cookie("session", &token.0.to_string());
        let result = scheme.validator().validate(&parts).await;
        assert!(result.is_err(), "revoked session must not validate");
    }

    #[tokio::test]
    async fn missing_cookie_is_rejected() {
        let scheme = scheme_with_user("user@example.com", "passwordpassword").await;
        let parts = http::Request::builder()
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let result = scheme.validator().validate(&parts).await;
        assert!(matches!(result, Err(SessionAuthError::MissingSession)));
    }

    fn parts_with_cookie(name: &str, value: &str) -> http::request::Parts {
        http::Request::builder()
            .header("cookie", format!("{}={}", name, value))
            .body(())
            .unwrap()
            .into_parts()
            .0
    }
}
