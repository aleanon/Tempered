//! The token mechanism, factored out of the credential scheme.
//!
//! `JwtScheme` and `SessionScheme` are the *same* scheme — authenticate
//! credentials, then issue / validate / revoke a token in a cookie — differing
//! only in how the token is represented (a signed JWT vs a server-side session
//! id). [`TokenStrategy`] is exactly that seam: everything else
//! ([`CredentialScheme`](crate::authentication::credential_scheme::CredentialScheme)
//! and its capabilities) is written once, generic over the strategy.

use async_trait::async_trait;
use secrecy::ExposeSecret;
use tempered_core::{
    AuthRequest, AuthValidator, BannedTokenStore, BannedTokenStoreError, Email, IntoStatusMessage,
};
use thiserror::Error;

use crate::auth_validation::local_jwt_validator::{
    JwtAuthConfig, LocalJwtValidator, TokenAuthError, create_auth_cookie, generate_auth_token,
};

/// How a credential scheme mints, validates, and revokes its session token.
///
/// The bound is required only where a concrete strategy is *constructed*; the
/// generic credential scheme calls these methods without ever naming JWT or
/// session details.
#[async_trait]
pub trait TokenStrategy: Clone + Send + Sync + 'static {
    /// The token handed to the client (and read back on later requests).
    type Token: Clone + Send + Sync + 'static;
    /// The validator the middleware runs on protected routes.
    type Validator: AuthValidator<RequestParts = http::request::Parts>;
    /// Errors from issuing/revoking (validation errors belong to the validator).
    type Error: std::error::Error + Send + Sync + 'static + IntoStatusMessage;

    /// Mint a token for an already-verified identity.
    async fn issue(&self, email: &Email) -> Result<Self::Token, Self::Error>;

    /// Invalidate a token (logout / ban / delete).
    async fn revoke(&self, token: &Self::Token) -> Result<(), Self::Error>;

    /// The validator middleware uses.
    fn validator(&self) -> &Self::Validator;

    /// The cookie this token lives in.
    fn cookie_name(&self) -> &str;

    /// Build the full `Set-Cookie` value delivering `token` (the format — TTL,
    /// flags — is the strategy's concern).
    fn auth_cookie(&self, token: &Self::Token) -> String;

    /// Pull the token back out of a request.
    fn extract<R: AuthRequest>(&self, req: &R) -> Option<Self::Token>;
}

// ============================================================================
// JWT token type
// ============================================================================

/// A signed JWT delivered to / read from the client.
#[derive(Debug, Clone)]
pub struct JwtToken(pub String);

impl JwtToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<String> for JwtToken {
    fn from(s: String) -> Self {
        JwtToken(s)
    }
}

// ============================================================================
// JWT strategy
// ============================================================================

/// Stateless JWT tokens: `issue` signs, `revoke` bans, validation is local
/// signature + ban-list checking.
#[derive(Clone)]
pub struct JwtTokens<B> {
    config: JwtAuthConfig,
    banned: B,
    validator: LocalJwtValidator<B>,
}

impl<B> JwtTokens<B>
where
    B: BannedTokenStore + Clone,
{
    pub fn new(config: JwtAuthConfig, banned: B) -> Self {
        let validator = LocalJwtValidator::new(banned.clone(), config.clone());
        Self {
            config,
            banned,
            validator,
        }
    }
}

#[async_trait]
impl<B> TokenStrategy for JwtTokens<B>
where
    B: BannedTokenStore + Clone + Send + Sync + 'static,
{
    type Token = JwtToken;
    type Validator = LocalJwtValidator<B>;
    type Error = JwtTokenError;

    async fn issue(&self, email: &Email) -> Result<JwtToken, JwtTokenError> {
        let token = generate_auth_token(
            email,
            self.config.token_ttl_in_seconds,
            self.config.jwt_secret.expose_secret().as_bytes(),
        )
        .map_err(JwtTokenError::Generate)?;
        Ok(JwtToken(token))
    }

    async fn revoke(&self, token: &JwtToken) -> Result<(), JwtTokenError> {
        self.banned
            .ban_token(token.0.clone())
            .await
            .map_err(JwtTokenError::Revoke)?;
        Ok(())
    }

    fn validator(&self) -> &LocalJwtValidator<B> {
        &self.validator
    }

    fn cookie_name(&self) -> &str {
        &self.config.jwt_cookie_name
    }

    fn auth_cookie(&self, token: &JwtToken) -> String {
        let max_age = time::Duration::seconds(self.config.token_ttl_in_seconds as i64);
        create_auth_cookie(
            token.0.clone(),
            &self.config.jwt_cookie_name,
            Some(max_age),
        )
        .to_string()
    }

    fn extract<R: AuthRequest>(&self, req: &R) -> Option<JwtToken> {
        req.cookie(&self.config.jwt_cookie_name)
            .map(|s| JwtToken(s.to_string()))
    }
}

/// Errors from the JWT strategy's issue/revoke steps.
#[derive(Debug, Error)]
pub enum JwtTokenError {
    #[error("Token error: {0}")]
    Generate(TokenAuthError),
    #[error("Failed to ban JWT token: {0}")]
    Revoke(BannedTokenStoreError),
}

impl IntoStatusMessage for JwtTokenError {
    fn into_status_message(self) -> (http::StatusCode, String) {
        match self {
            // Preserve the previous mapping: a token (signing/decoding) error uses
            // its own status; a ban-store failure is a 500.
            JwtTokenError::Generate(e) => e.into_status_message(),
            JwtTokenError::Revoke(e) => (
                http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Token store error: {}", e),
            ),
        }
    }
}
