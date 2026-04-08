//! Concrete implementations of composable authentication blocks.
//!
//! This module provides ready-to-use implementations of the authentication block
//! traits defined in `tempered_core::composable`.

use async_trait::async_trait;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use tempered_core::{
    BannedTokenStore, Email, Password, User, UserError, UserStore, UserStoreError,
    composable::{AuthenticationBlock, RegistrationBlock, SchemeContext},
};
use thiserror::Error;

use crate::auth_validation::local_jwt_validator::{
    JwtAuthConfig, LocalJwtValidator, TokenAuthError, generate_auth_token,
};

// ============================================================================
// JWT Authentication Block
// ============================================================================

/// JWT-based authentication block.
///
/// This block provides password-based authentication that issues JWT tokens.
#[derive(Clone)]
pub struct JwtAuthBlock {
    jwt_config: JwtAuthConfig,
}

impl JwtAuthBlock {
    /// Create a new JWT authentication block.
    pub fn new(jwt_config: JwtAuthConfig) -> Self {
        Self { jwt_config }
    }

    /// Create a new JWT authentication block with basic configuration.
    pub fn with_secret(
        jwt_secret: Secret<String>,
        token_ttl_seconds: u64,
        cookie_name: String,
    ) -> Self {
        let config = JwtAuthConfig {
            jwt_secret,
            token_ttl_in_seconds: token_ttl_seconds,
            jwt_cookie_name: cookie_name,
        };
        Self::new(config)
    }
}

/// JWT token type
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JwtToken(pub String);

/// Email/password credentials for JWT authentication
#[derive(Debug, Deserialize)]
pub struct EmailPasswordCredentials {
    pub email: String,
    pub password: String,
}

/// Errors that can occur during JWT authentication
#[derive(Debug, Error)]
pub enum JwtAuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("User not found")]
    UserNotFound,

    #[error("Invalid email format: {0}")]
    InvalidEmail(#[from] UserError),

    #[error("User store error: {0}")]
    UserStoreError(#[from] UserStoreError),

    #[error("Token generation error: {0}")]
    TokenError(#[from] TokenAuthError),
}

#[async_trait]
impl<U, T> AuthenticationBlock<U, T> for JwtAuthBlock
where
    U: UserStore + Clone,
    T: BannedTokenStore + Clone + 'static,
{
    type Credentials = EmailPasswordCredentials;
    type Token = JwtToken;
    type AuthError = JwtAuthError;
    type Validator = LocalJwtValidator<T>;

    async fn authenticate(
        &self,
        ctx: &SchemeContext<U, T>,
        creds: Self::Credentials,
    ) -> Result<Self::Token, Self::AuthError> {
        // Convert string credentials to Email and Password types
        let email = Email::try_from(Secret::new(creds.email))?;
        let password = Password::try_from(Secret::new(creds.password))
            .map_err(|_| JwtAuthError::InvalidCredentials)?;

        // Get the user from the store
        let user = ctx
            .user_store
            .get_user(&email)
            .await
            .map_err(|_| JwtAuthError::UserNotFound)?;

        // Verify the password
        if !user.password_matches(&password) {
            return Err(JwtAuthError::InvalidCredentials);
        }

        // Generate JWT token
        let token_string = generate_auth_token(
            &email,
            self.jwt_config.token_ttl_in_seconds,
            self.jwt_config.jwt_secret.expose_secret().as_bytes(),
        )?;

        Ok(JwtToken(token_string))
    }

    fn create_validator(&self, ctx: &SchemeContext<U, T>) -> Self::Validator {
        // Clone the inner store from the Arc
        LocalJwtValidator::new((*ctx.token_store).clone(), self.jwt_config.clone())
    }

    async fn authenticate_after_2fa(
        &self,
        _ctx: &SchemeContext<U, T>,
        email: Email,
    ) -> Result<Self::Token, Self::AuthError> {
        // Generate JWT token after successful 2FA
        let token_string = generate_auth_token(
            &email,
            self.jwt_config.token_ttl_in_seconds,
            self.jwt_config.jwt_secret.expose_secret().as_bytes(),
        )?;

        Ok(JwtToken(token_string))
    }
}

// ============================================================================
// Email/Password Registration Block
// ============================================================================

/// Email/password user registration block.
///
/// This block handles new user registration with email and password.
#[derive(Clone)]
pub struct EmailPasswordRegistrationBlock;

impl EmailPasswordRegistrationBlock {
    /// Create a new email/password registration block.
    pub fn new() -> Self {
        Self
    }
}

impl Default for EmailPasswordRegistrationBlock {
    fn default() -> Self {
        Self::new()
    }
}

/// No additional registration data needed for basic email/password registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoRegistrationData;

/// Errors that can occur during registration
#[derive(Debug, Error)]
pub enum RegistrationError {
    #[error("Email already exists")]
    EmailAlreadyExists,

    #[error("User store error: {0}")]
    UserStoreError(#[from] UserStoreError),
}

#[async_trait]
impl<U, T> RegistrationBlock<U, T> for EmailPasswordRegistrationBlock
where
    U: UserStore + Clone,
    T: BannedTokenStore + Clone + 'static,
{
    type RegistrationData = NoRegistrationData;
    type RegistrationError = RegistrationError;

    async fn register(
        &self,
        ctx: &SchemeContext<U, T>,
        email: Email,
        password: Password,
        _data: Self::RegistrationData,
    ) -> Result<(), Self::RegistrationError> {
        // Check if user already exists
        if ctx.user_store.get_user(&email).await.is_ok() {
            return Err(RegistrationError::EmailAlreadyExists);
        }

        // Create new user
        let user = User::new(email, password, false);
        ctx.user_store.add_user(user).await?;

        Ok(())
    }
}
