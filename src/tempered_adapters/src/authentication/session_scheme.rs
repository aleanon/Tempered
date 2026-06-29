//! Opaque server-side session scheme — the session specialization of
//! [`CredentialScheme`](crate::authentication::credential_scheme::CredentialScheme).
//!
//! `SessionScheme` is a type alias over `CredentialScheme<U, SessionTokens<S>, …>`:
//! it is the same credential scheme as [`JwtScheme`](crate::authentication::jwt_scheme::JwtScheme),
//! just with the stateful [`SessionTokens`] strategy plugged in — so it inherits
//! the whole capability suite (2FA, elevation, registration, password reset,
//! email verification, OAuth, passkeys). Login verifies the password, creates a
//! server-side session in a [`SessionStore`], and returns the random
//! [`SessionId`] in an HttpOnly cookie; because the session lives server-side,
//! logout (or any revocation) invalidates it instantly.
//!
//! Note: unlike the previous standalone scheme, a 2FA-flagged user logging into a
//! session scheme *without* `supports_2fa` now errors (consistent with JWT)
//! rather than being granted a session immediately.

use async_trait::async_trait;
use axum_extra::extract::CookieJar;
use tempered_core::{
    AuthRequest, AuthValidator, Email, IntoStatusMessage, SessionId, SessionStore,
    SessionStoreError, UserStore,
};
use thiserror::Error;

use crate::authentication::credential_scheme::{CredentialScheme, Elevation};
use crate::authentication::token_strategy::TokenStrategy;

// ============================================================================
// Configuration
// ============================================================================

#[derive(Clone)]
pub struct SessionConfig {
    pub cookie_name: String,
    pub ttl_in_seconds: u64,
}

// ============================================================================
// Token type
// ============================================================================

/// Opaque session token delivered to the client (wraps a `SessionId`).
#[derive(Clone, Debug)]
pub struct SessionToken(pub SessionId);

// ============================================================================
// Session token strategy
// ============================================================================

fn build_session_cookie(value: &str, name: &str, ttl_seconds: u64) -> String {
    format!(
        "{}={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
        name, value, ttl_seconds
    )
}

/// Stateful session tokens: `issue` creates a server-side session, `revoke`
/// deletes it, validation is a store lookup (with sliding expiry).
#[derive(Clone)]
pub struct SessionTokens<S> {
    store: S,
    config: SessionConfig,
    validator: SessionValidator<S>,
}

impl<S> SessionTokens<S>
where
    S: SessionStore + Clone,
{
    pub fn new(store: S, config: SessionConfig) -> Self {
        let validator = SessionValidator::new(store.clone(), config.clone());
        Self {
            store,
            config,
            validator,
        }
    }
}

#[async_trait]
impl<S> TokenStrategy for SessionTokens<S>
where
    S: SessionStore + Clone + Send + Sync + 'static,
{
    type Token = SessionToken;
    type Validator = SessionValidator<S>;
    type Error = SessionError;

    async fn issue(&self, email: &Email) -> Result<SessionToken, SessionError> {
        let id = SessionId::new();
        self.store.create_session(id.clone(), email.clone()).await?;
        Ok(SessionToken(id))
    }

    async fn revoke(&self, token: &SessionToken) -> Result<(), SessionError> {
        self.store.delete_session(&token.0).await?;
        Ok(())
    }

    fn validator(&self) -> &SessionValidator<S> {
        &self.validator
    }

    fn cookie_name(&self) -> &str {
        &self.config.cookie_name
    }

    fn auth_cookie(&self, token: &SessionToken) -> String {
        build_session_cookie(
            &token.0.to_string(),
            &self.config.cookie_name,
            self.config.ttl_in_seconds,
        )
    }

    fn extract<R: AuthRequest>(&self, req: &R) -> Option<SessionToken> {
        req.cookie(&self.config.cookie_name)
            .and_then(SessionId::parse)
            .map(SessionToken)
    }
}

// ============================================================================
// Scheme alias + session-specific constructors
// ============================================================================

/// Server-side session credential scheme: [`CredentialScheme`] with the session
/// token strategy. Slots match [`CredentialScheme`].
pub type SessionScheme<U, S, F = (), L = (), R = (), M = (), O = (), K = ()> =
    CredentialScheme<U, SessionTokens<S>, F, L, R, M, O, K>;

impl<U, S> CredentialScheme<U, SessionTokens<S>, (), (), (), (), (), ()>
where
    U: UserStore,
    S: SessionStore + Clone + Send + Sync + 'static,
{
    /// Create the session scheme: password login, logout, and session validation.
    ///
    /// Opt into optional capabilities with the `supports_*` methods.
    pub fn new(user_store: U, session_store: S, config: SessionConfig) -> Self {
        Self::from_tokens(user_store, SessionTokens::new(session_store, config))
    }
}

impl<U, S, F, R, M, O, K> CredentialScheme<U, SessionTokens<S>, F, (), R, M, O, K>
where
    S: SessionStore + Clone + Send + Sync + 'static,
{
    /// Enable elevated ("sudo") sessions from a separate store + config, lighting
    /// up [`SupportsElevation`](tempered_core::SupportsElevation).
    pub fn supports_elevation(
        self,
        elevated_session_store: S,
        elevated_config: SessionConfig,
    ) -> CredentialScheme<U, SessionTokens<S>, F, Elevation<SessionTokens<S>>, R, M, O, K> {
        self.supports_elevation_with(SessionTokens::new(elevated_session_store, elevated_config))
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
    type Error = SessionError;

    async fn validate(&self, parts: &Self::RequestParts) -> Result<Self::Claims, Self::Error> {
        let jar = CookieJar::from_headers(&parts.headers);

        let raw = jar
            .get(&self.cookie_name)
            .map(|c| c.value().to_string())
            .filter(|v| !v.is_empty())
            .ok_or(SessionError::MissingSession)?;

        let id = SessionId::parse(&raw).ok_or(SessionError::InvalidSession)?;

        let email = self.session_store.get_session(&id).await?;

        // Best-effort sliding expiry; failure to touch shouldn't reject a request
        // that just validated successfully.
        let _ = self.session_store.touch_session(&id).await;

        Ok(SessionClaims { email })
    }
}

// ============================================================================
// Errors (shared by the strategy's issue/revoke and the validator)
// ============================================================================

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Missing session cookie")]
    MissingSession,
    #[error("Invalid session")]
    InvalidSession,
    #[error("Session store error: {0}")]
    Store(#[from] SessionStoreError),
}

impl IntoStatusMessage for SessionError {
    fn into_status_message(self) -> (http::StatusCode, String) {
        match self {
            SessionError::MissingSession => {
                (http::StatusCode::UNAUTHORIZED, "Missing session".to_string())
            }
            SessionError::InvalidSession => {
                (http::StatusCode::UNAUTHORIZED, "Invalid session".to_string())
            }
            SessionError::Store(SessionStoreError::SessionNotFound) => (
                http::StatusCode::UNAUTHORIZED,
                "Session not found or expired".to_string(),
            ),
            SessionError::Store(SessionStoreError::UnexpectedError(m)) => {
                (http::StatusCode::INTERNAL_SERVER_ERROR, m)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionConfig, SessionError, SessionScheme};
    use crate::authentication::credential_scheme::{CredentialError, PasswordCredentials};
    use crate::persistence::hashmap_session_store::HashMapSessionStore;
    use crate::persistence::hashmap_user_store::HashMapUserStore;
    use secrecy::Secret;
    use tempered_core::{
        AuthValidator, AuthenticationScheme, Email, LoginOutcome, Password, SupportsElevation, User,
        UserStore,
    };

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

    fn credentials(email: &str, password: &str) -> PasswordCredentials {
        PasswordCredentials {
            email: Secret::new(email.to_string()),
            password: Secret::new(password.to_string()),
        }
    }

    fn parts_with_cookie(name: &str, value: &str) -> http::request::Parts {
        http::Request::builder()
            .header("cookie", format!("{}={}", name, value))
            .body(())
            .unwrap()
            .into_parts()
            .0
    }

    #[tokio::test]
    async fn login_creates_session_and_validator_accepts_it() {
        let scheme = scheme_with_user("user@example.com", "passwordpassword").await;

        let outcome = scheme
            .login(credentials("user@example.com", "passwordpassword"))
            .await
            .unwrap();

        let token = match outcome {
            LoginOutcome::Success(t) => t,
            _ => panic!("expected immediate success"),
        };

        let parts = parts_with_cookie("session", &token.0.to_string());
        let claims = scheme.validator().validate(&parts).await.unwrap();
        assert_eq!(
            claims.email,
            Email::try_from(Secret::new("user@example.com".to_string())).unwrap()
        );
    }

    #[tokio::test]
    async fn logout_revokes_session_immediately() {
        let scheme = scheme_with_user("user@example.com", "passwordpassword").await;
        let outcome = scheme
            .login(credentials("user@example.com", "passwordpassword"))
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
        let parts = http::Request::builder().body(()).unwrap().into_parts().0;
        let result = scheme.validator().validate(&parts).await;
        assert!(matches!(result, Err(SessionError::MissingSession)));
    }

    /// Behavior change from the old standalone scheme: a 2FA-flagged user logging
    /// into a session scheme that did not opt into 2FA now errors (consistent
    /// with JWT), instead of being granted a session immediately.
    #[tokio::test]
    async fn twofa_user_without_2fa_support_is_rejected() {
        let user_store = HashMapUserStore::new();
        let user = User::parse(
            Secret::new("user@example.com".to_string()),
            Secret::new("passwordpassword".to_string()),
            true, // requires 2FA
        )
        .unwrap();
        user_store.add_user(user).await.unwrap();
        let scheme = SessionScheme::new(user_store, HashMapSessionStore::new(), config());

        let result = scheme
            .login(credentials("user@example.com", "passwordpassword"))
            .await;
        assert!(matches!(result, Err(CredentialError::TwoFaNotConfigured)));
    }

    /// A capability the standalone session scheme never had: elevation. The
    /// elevated session is minted in a separate store and validates via the
    /// elevated validator.
    #[tokio::test]
    async fn inherited_elevation_issues_a_validatable_elevated_session() {
        let user_store = HashMapUserStore::new();
        let user = User::parse(
            Secret::new("user@example.com".to_string()),
            Secret::new("passwordpassword".to_string()),
            false,
        )
        .unwrap();
        user_store.add_user(user).await.unwrap();

        let scheme = SessionScheme::new(user_store, HashMapSessionStore::new(), config())
            .supports_elevation(
                HashMapSessionStore::new(),
                SessionConfig {
                    cookie_name: "elevated_session".to_string(),
                    ttl_in_seconds: 300,
                },
            );

        let email = Email::try_from(Secret::new("user@example.com".to_string())).unwrap();
        let password = Password::try_from(Secret::new("passwordpassword".to_string())).unwrap();
        let elevated = scheme.elevate(email, password).await.unwrap();

        let parts = parts_with_cookie("elevated_session", &elevated.0.to_string());
        let claims = scheme.elevated_validator().validate(&parts).await.unwrap();
        assert_eq!(
            claims.email,
            Email::try_from(Secret::new("user@example.com".to_string())).unwrap()
        );
    }
}
