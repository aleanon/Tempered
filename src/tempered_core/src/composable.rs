//! Composable building block architecture for authentication schemes.
//!
//! This module provides a flexible, type-safe way to compose authentication schemes
//! from reusable building blocks. Instead of a monolithic scheme that implements all
//! capabilities, you can compose only the features you need.
//!
//! # Example
//!
//! ```ignore
//! use tempered_core::composable::*;
//!
//! let scheme = SchemeBuilder::new()
//!     .with_user_store(user_store)
//!     .with_token_store(token_store)
//!     .with_jwt_auth(jwt_secret, Duration::from_secs(3600))
//!     .with_registration::<UserMetadata>()
//!     .with_email_2fa(email_client, code_store)
//!     .build()?;
//! ```

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    Email, Password, TwoFaAttemptId, TwoFaCode,
    ports::repositories::{BannedTokenStore, UserStore},
};

// ============================================================================
// Shared Context
// ============================================================================

/// Shared dependencies provided to all building blocks.
///
/// This context is passed to block methods so they can access common
/// dependencies without each block needing to store them.
///
/// Generic parameters allow zero-cost abstraction with no dynamic dispatch.
#[derive(Clone)]
pub struct SchemeContext<U, T>
where
    U: Clone,
    T: Clone,
{
    pub user_store: Arc<U>,
    pub token_store: Arc<T>,
}

// ============================================================================
// Block Traits
// ============================================================================

/// Authentication block provides core authentication functionality.
///
/// Blocks receive a `SchemeContext` with shared dependencies and use it
/// to authenticate users and create validators.
#[async_trait]
pub trait AuthenticationBlock<U, T>: Send + Sync + Clone + 'static
where
    U: UserStore + Clone,
    T: BannedTokenStore + Clone,
{
    /// The credentials type this block accepts
    type Credentials: for<'de> Deserialize<'de> + Send;

    /// The token type this block produces
    type Token: Clone + Send + Sync;

    /// Authentication errors
    type AuthError: std::error::Error + Send + Sync;

    /// Token validator
    type Validator: crate::AuthValidator;

    /// Authenticate a user with the given credentials
    async fn authenticate(
        &self,
        ctx: &SchemeContext<U, T>,
        creds: Self::Credentials,
    ) -> Result<Self::Token, Self::AuthError>;

    /// Create a validator for this authentication block
    fn create_validator(&self, ctx: &SchemeContext<U, T>) -> Self::Validator;

    /// Generate a token for a user after successful 2FA verification
    async fn authenticate_after_2fa(
        &self,
        ctx: &SchemeContext<U, T>,
        email: Email,
    ) -> Result<Self::Token, Self::AuthError>;
}

/// Registration block provides user registration functionality.
#[async_trait]
pub trait RegistrationBlock<U, T>: Send + Sync + Clone + 'static
where
    U: UserStore + Clone,
    T: BannedTokenStore + Clone,
{
    /// Additional registration data required
    type RegistrationData: for<'de> Deserialize<'de> + Serialize + Send;

    /// Registration errors
    type RegistrationError: std::error::Error + Send + Sync;

    /// Register a new user
    async fn register(
        &self,
        ctx: &SchemeContext<U, T>,
        email: Email,
        password: Password,
        data: Self::RegistrationData,
    ) -> Result<(), Self::RegistrationError>;
}

/// Two-factor authentication block.
#[async_trait]
pub trait TwoFactorBlock<U, T>: Send + Sync + Clone + 'static
where
    U: UserStore + Clone,
    T: BannedTokenStore + Clone,
{
    /// 2FA errors
    type TwoFactorError: std::error::Error + Send + Sync;

    /// Send a 2FA code to the user
    async fn send_code(
        &self,
        ctx: &SchemeContext<U, T>,
        email: &Email,
        attempt_id: TwoFaAttemptId,
    ) -> Result<(), Self::TwoFactorError>;

    /// Verify a 2FA code
    async fn verify_code(
        &self,
        ctx: &SchemeContext<U, T>,
        email: Email,
        attempt_id: TwoFaAttemptId,
        code: TwoFaCode,
    ) -> Result<(), Self::TwoFactorError>;
}

/// Elevation block provides privilege elevation functionality.
#[async_trait]
pub trait ElevationBlock<U, T>: Send + Sync + Clone + 'static
where
    U: UserStore + Clone,
    T: BannedTokenStore + Clone,
{
    /// The elevated token type
    type ElevatedToken: Clone + Send + Sync;

    /// Elevation errors
    type ElevationError: std::error::Error + Send + Sync;

    /// Elevated token validator
    type ElevatedValidator: crate::AuthValidator;

    /// Elevate privileges for a user
    async fn elevate(
        &self,
        ctx: &SchemeContext<U, T>,
        email: Email,
        password: Password,
    ) -> Result<Self::ElevatedToken, Self::ElevationError>;

    /// Create a validator for elevated tokens
    fn create_elevated_validator(&self, ctx: &SchemeContext<U, T>) -> Self::ElevatedValidator;
}

// ============================================================================
// Marker Types (for type-state pattern)
// ============================================================================

/// Marker type indicating no authentication block
#[derive(Clone)]
pub struct NoAuth;

/// Marker type indicating no registration block
#[derive(Clone)]
pub struct NoReg;

/// Marker type indicating no 2FA block
#[derive(Clone)]
pub struct No2Fa;

/// Marker type indicating no elevation block
#[derive(Clone)]
pub struct NoElev;

// ============================================================================
// Scheme Builder
// ============================================================================

/// Builder for composing authentication schemes from building blocks.
///
/// The builder uses the type-state pattern to track which capabilities
/// have been added. Each `with_*` method changes the builder's type.
///
/// Generic parameters U and T are the concrete types for UserStore and BannedTokenStore.
pub struct SchemeBuilder<U, T, Auth = NoAuth, Reg = NoReg, TwoFa = No2Fa, Elev = NoElev> {
    user_store: Option<Arc<U>>,
    token_store: Option<Arc<T>>,
    auth: Auth,
    registration: Reg,
    two_fa: TwoFa,
    elevation: Elev,
}

impl<U, T> SchemeBuilder<U, T> {
    /// Create a new scheme builder with no capabilities.
    pub fn new() -> Self {
        SchemeBuilder {
            user_store: None,
            token_store: None,
            auth: NoAuth,
            registration: NoReg,
            two_fa: No2Fa,
            elevation: NoElev,
        }
    }
}

impl<U, T> Default for SchemeBuilder<U, T> {
    fn default() -> Self {
        Self::new()
    }
}

// Shared dependency setters (available at any time)
impl<U, T, Auth, Reg, TwoFa, Elev> SchemeBuilder<U, T, Auth, Reg, TwoFa, Elev> {
    /// Add a user store (shared dependency).
    pub fn with_user_store(mut self, store: Arc<U>) -> Self {
        self.user_store = Some(store);
        self
    }

    /// Add a banned token store (shared dependency).
    pub fn with_token_store(mut self, store: Arc<T>) -> Self {
        self.token_store = Some(store);
        self
    }
}

// ============================================================================
// Build Error
// ============================================================================

/// Errors that can occur when building a composed scheme.
#[derive(Debug, Clone)]
pub enum BuildError {
    /// User store was not provided
    MissingUserStore,

    /// Token store was not provided
    MissingTokenStore,
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::MissingUserStore => {
                write!(
                    f,
                    "User store is required. Call .with_user_store() before .build()"
                )
            }
            BuildError::MissingTokenStore => {
                write!(
                    f,
                    "Token store is required. Call .with_token_store() before .build()"
                )
            }
        }
    }
}

impl std::error::Error for BuildError {}

// ============================================================================
// Build Method (requires AuthenticationBlock)
// ============================================================================

impl<U, T, Auth, Reg, TwoFa, Elev> SchemeBuilder<U, T, Auth, Reg, TwoFa, Elev>
where
    U: UserStore + Clone,
    T: BannedTokenStore + Clone,
    Auth: AuthenticationBlock<U, T>,
    Reg: Clone,
    TwoFa: Clone,
    Elev: Clone,
{
    /// Build the composed scheme (without elevation support).
    ///
    /// This validates that all required shared dependencies have been provided
    /// and creates the final ComposedScheme.
    ///
    /// # Errors
    ///
    /// Returns an error if user_store or token_store were not provided.
    pub fn build(
        self,
    ) -> Result<ComposedScheme<U, T, Auth, Reg, TwoFa, Elev, NoElevValidator>, BuildError> {
        let user_store = self.user_store.ok_or(BuildError::MissingUserStore)?;
        let token_store = self.token_store.ok_or(BuildError::MissingTokenStore)?;

        let context = SchemeContext {
            user_store,
            token_store,
        };

        // Create validator once during build
        let validator = self.auth.create_validator(&context);

        Ok(ComposedScheme {
            context,
            auth: self.auth,
            validator,
            registration: self.registration,
            two_fa: self.two_fa,
            elevation: self.elevation,
            elevated_validator: NoElevValidator,
        })
    }
}

// Build method for schemes WITH elevation support
impl<U, T, Auth, Reg, TwoFa, Elev> SchemeBuilder<U, T, Auth, Reg, TwoFa, Elev>
where
    U: UserStore + Clone,
    T: BannedTokenStore + Clone,
    Auth: AuthenticationBlock<U, T>,
    Reg: Clone,
    TwoFa: Clone,
    Elev: ElevationBlock<U, T>,
{
    /// Build the composed scheme with elevation support.
    ///
    /// This validates that all required shared dependencies have been provided
    /// and creates the final ComposedScheme with an elevated validator.
    ///
    /// # Errors
    ///
    /// Returns an error if user_store or token_store were not provided.
    pub fn build_with_elevation(
        self,
    ) -> Result<ComposedScheme<U, T, Auth, Reg, TwoFa, Elev, Elev::ElevatedValidator>, BuildError>
    {
        let user_store = self.user_store.ok_or(BuildError::MissingUserStore)?;
        let token_store = self.token_store.ok_or(BuildError::MissingTokenStore)?;

        let context = SchemeContext {
            user_store,
            token_store,
        };

        // Create both validators during build
        let validator = self.auth.create_validator(&context);
        let elevated_validator = self.elevation.create_elevated_validator(&context);

        Ok(ComposedScheme {
            context,
            auth: self.auth,
            validator,
            registration: self.registration,
            two_fa: self.two_fa,
            elevation: self.elevation,
            elevated_validator,
        })
    }
}

// ============================================================================
// Composed Scheme
// ============================================================================

/// A composed authentication scheme built from building blocks.
///
/// This type is generic over the blocks that were added during building.
/// It only implements traits for the capabilities that were actually added.
///
/// Generic parameters U and T are the concrete store types (zero-cost abstraction).
pub struct ComposedScheme<U, T, Auth, Reg, TwoFa, Elev, ElevVal = NoElevValidator>
where
    U: UserStore + Clone,
    T: BannedTokenStore + Clone,
    Auth: AuthenticationBlock<U, T>,
{
    context: SchemeContext<U, T>,
    auth: Auth,
    validator: Auth::Validator,
    registration: Reg,
    two_fa: TwoFa,
    elevation: Elev,
    elevated_validator: ElevVal,
}

/// Marker type indicating no elevated validator
#[derive(Clone)]
pub struct NoElevValidator;

impl<U, T, Auth, Reg, TwoFa, Elev, ElevVal> Clone
    for ComposedScheme<U, T, Auth, Reg, TwoFa, Elev, ElevVal>
where
    U: UserStore + Clone,
    T: BannedTokenStore + Clone,
    Auth: AuthenticationBlock<U, T>,
    Reg: Clone,
    TwoFa: Clone,
    Elev: Clone,
    ElevVal: Clone,
{
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            auth: self.auth.clone(),
            validator: self.validator.clone(),
            registration: self.registration.clone(),
            two_fa: self.two_fa.clone(),
            elevation: self.elevation.clone(),
            elevated_validator: self.elevated_validator.clone(),
        }
    }
}

// ============================================================================
// Trait Implementations for ComposedScheme
// ============================================================================

use crate::strategies::authenticator::{
    AuthenticationScheme, LoginOutcome, SupportsElevation, SupportsRegistration, SupportsTwoFactor,
};

// AuthenticationScheme - Always implemented if we have an Auth block
#[async_trait]
impl<U, T, Auth, Reg, TwoFa, Elev, ElevVal> AuthenticationScheme
    for ComposedScheme<U, T, Auth, Reg, TwoFa, Elev, ElevVal>
where
    U: UserStore + Clone + 'static,
    T: BannedTokenStore + Clone + 'static,
    Auth: AuthenticationBlock<U, T>,
    Reg: Clone + Send + Sync + 'static,
    TwoFa: Clone + Send + Sync + 'static,
    Elev: Clone + Send + Sync + 'static,
    ElevVal: Clone + Send + Sync + 'static,
{
    type Credentials = Auth::Credentials;
    type Token = Auth::Token;
    type AuthError = Auth::AuthError;
    type Validator = Auth::Validator;
    type LogoutOutput = String;

    async fn login(
        &self,
        creds: Self::Credentials,
    ) -> Result<LoginOutcome<Self::Token>, Self::AuthError> {
        let token = self.auth.authenticate(&self.context, creds).await?;
        Ok(LoginOutcome::Success(token))
    }

    fn validator(&self) -> &Self::Validator {
        &self.validator
    }

    async fn logout(&self, _token: &Self::Token) -> Result<Self::LogoutOutput, Self::AuthError> {
        // Default implementation - just return success message
        Ok("Logged out successfully".to_string())
    }
}

// SupportsRegistration - Only implemented if we have a Reg block (not NoReg)
#[async_trait]
impl<U, T, Auth, Reg, TwoFa, Elev, ElevVal> SupportsRegistration
    for ComposedScheme<U, T, Auth, Reg, TwoFa, Elev, ElevVal>
where
    U: UserStore + Clone + 'static,
    T: BannedTokenStore + Clone + 'static,
    Auth: AuthenticationBlock<U, T>,
    Reg: RegistrationBlock<U, T>,
    TwoFa: Clone + Send + Sync + 'static,
    Elev: Clone + Send + Sync + 'static,
    ElevVal: Clone + Send + Sync + 'static,
{
    type RegistrationData = Reg::RegistrationData;
    type RegistrationError = Reg::RegistrationError;

    async fn register(
        &self,
        email: Email,
        password: Password,
        data: Self::RegistrationData,
    ) -> Result<(), Self::RegistrationError> {
        self.registration
            .register(&self.context, email, password, data)
            .await
    }
}

// SupportsTwoFactor - Only implemented if we have a TwoFa block
#[async_trait]
impl<U, T, Auth, Reg, TwoFa, Elev, ElevVal> SupportsTwoFactor
    for ComposedScheme<U, T, Auth, Reg, TwoFa, Elev, ElevVal>
where
    U: UserStore + Clone + 'static,
    T: BannedTokenStore + Clone + 'static,
    Auth: AuthenticationBlock<U, T>,
    Reg: Clone + Send + Sync + 'static,
    TwoFa: TwoFactorBlock<U, T>,
    Elev: Clone + Send + Sync + 'static,
    ElevVal: Clone + Send + Sync + 'static,
{
    type TwoFactorError = TwoFa::TwoFactorError;

    async fn verify_2fa(
        &self,
        email: Email,
        attempt_id: TwoFaAttemptId,
        code: TwoFaCode,
    ) -> Result<Self::Token, Self::TwoFactorError> {
        self.two_fa
            .verify_code(&self.context, email.clone(), attempt_id, code)
            .await?;

        // After successful 2FA, generate a token
        // Note: This requires AuthError to be convertible to TwoFactorError
        // In practice, the block implementations will handle this
        self.auth
            .authenticate_after_2fa(&self.context, email)
            .await
            .map_err(|_| panic!("AuthError to TwoFactorError conversion not implemented"))
    }
}

// SupportsElevation - Only implemented if we have an Elev block AND an ElevatedValidator
#[async_trait]
impl<U, T, Auth, Reg, TwoFa, Elev> SupportsElevation
    for ComposedScheme<U, T, Auth, Reg, TwoFa, Elev, Elev::ElevatedValidator>
where
    U: UserStore + Clone + 'static,
    T: BannedTokenStore + Clone + 'static,
    Auth: AuthenticationBlock<U, T>,
    Reg: Clone + Send + Sync + 'static,
    TwoFa: Clone + Send + Sync + 'static,
    Elev: ElevationBlock<U, T>,
{
    type ElevatedToken = Elev::ElevatedToken;
    type ElevationError = Elev::ElevationError;
    type ElevatedValidator = Elev::ElevatedValidator;

    async fn elevate(
        &self,
        email: Email,
        password: Password,
    ) -> Result<Self::ElevatedToken, Self::ElevationError> {
        self.elevation.elevate(&self.context, email, password).await
    }

    fn elevated_validator(&self) -> &Self::ElevatedValidator {
        &self.elevated_validator
    }

    async fn revoke_elevated_token(
        &self,
        _elevated_token: &Self::ElevatedToken,
    ) -> Result<(), Self::ElevationError> {
        // Default implementation - no-op
        Ok(())
    }
}
