use async_trait::async_trait;
use serde::Deserialize;

use crate::{
    domain::{
        email::Email, password::Password, two_fa_attempt_id::TwoFaAttemptId, two_fa_code::TwoFaCode,
    },
    strategies::auth_validator::AuthValidator,
};

// ============================================================================
// Core Authentication Scheme Trait
// ============================================================================

/// Core trait that all authentication schemes must implement.
///
/// An authentication scheme defines how users authenticate and how tokens/sessions
/// are validated. All schemes must support login (authentication), but other
/// capabilities like registration or 2FA are optional.
#[async_trait]
pub trait AuthenticationScheme: Send + Sync + Clone + 'static {
    /// The type of token/session identifier this scheme produces (e.g., JWT string, session ID)
    type Token: Clone + Send + Sync;

    type LogoutOutput;

    /// The validator that can verify tokens produced by this scheme
    type Validator: AuthValidator;

    /// The credentials this scheme expects for login
    type Credentials: for<'de> Deserialize<'de> + Send;

    /// Errors that can occur during login
    type AuthError: std::error::Error + Send + Sync + 'static;

    /// Authenticate a user with the provided credentials.
    ///
    /// This is the core capability - all authentication schemes must be able
    /// to verify credentials and produce a token/session.
    async fn login(
        &self,
        credentials: Self::Credentials,
    ) -> Result<LoginOutcome<Self::Token>, Self::AuthError>;

    async fn logout(&self, token: &Self::Token) -> Result<Self::LogoutOutput, Self::AuthError>;

    /// Get the validator for this scheme.
    ///
    /// The validator will be used by middleware to verify tokens on protected routes.
    fn validator(&self) -> &Self::Validator;
}

// ============================================================================
// Login Outcome - Domain Type
// ============================================================================

/// The result of a login attempt.
///
/// Some authentication schemes require a second factor (2FA) before issuing a token.
/// This type models both successful authentication and partial success requiring 2FA.
#[derive(Debug, Clone)]
pub enum LoginOutcome<T> {
    /// Login succeeded immediately, token is ready to use
    Success(T),

    /// Login succeeded but requires 2FA verification before issuing token
    Requires2Fa {
        email: Email,
        attempt_id: TwoFaAttemptId,
    },
}

// ============================================================================
// Optional Capability: Registration
// ============================================================================

/// Optional trait for authentication schemes that support self-service user registration.
///
/// Not all schemes support registration:
/// - JWT password schemes: YES (users can sign up)
/// - OAuth2: NO (accounts managed by third party)
/// - LDAP: NO (accounts managed by IT department)
/// - API keys: NO (keys issued by administrators)
#[async_trait]
pub trait SupportsRegistration: AuthenticationScheme {
    /// The data required to register a new user
    type RegistrationData: for<'de> Deserialize<'de> + Send;

    /// Errors that can occur during registration
    type RegistrationError: std::error::Error + Send + Sync + 'static;

    /// Register a new user account.
    async fn register(
        &self,
        email: Email,
        password: Password,
        data: Self::RegistrationData,
    ) -> Result<(), Self::RegistrationError>;
}

// ============================================================================
// Optional Capability: Two-Factor Authentication
// ============================================================================

/// Optional trait for authentication schemes that support two-factor authentication.
///
/// Schemes that implement this can require users to provide a second factor
/// (TOTP code, SMS code, etc.) after initial credential verification.
#[async_trait]
pub trait SupportsTwoFactor: AuthenticationScheme {
    /// Errors that can occur during 2FA verification
    type TwoFactorError: std::error::Error + Send + Sync + 'static;

    /// Verify a two-factor authentication code and issue a token.
    ///
    /// Called after a login attempt returns `LoginOutcome::Requires2Fa`.
    async fn verify_2fa(
        &self,
        email: Email,
        attempt_id: TwoFaAttemptId,
        code: TwoFaCode,
    ) -> Result<Self::Token, Self::TwoFactorError>;
}

// ============================================================================
// Optional Capability: OAuth2
// ============================================================================

/// Optional trait for authentication schemes that support OAuth2 flows.
///
/// OAuth2 schemes typically don't support password-based registration,
/// as user accounts are managed by the OAuth2 provider (Google, GitHub, etc.).
#[async_trait]
pub trait SupportsOAuth2: AuthenticationScheme {
    /// OAuth2 provider information
    type Provider: Send;

    /// The URL users should be redirected to for OAuth2 authorization
    type AuthorizationUrl: Send;

    /// Errors that can occur during OAuth2 flows
    type OAuth2Error: std::error::Error + Send + Sync + 'static;

    /// Begin an OAuth2 authorization flow.
    ///
    /// Returns a URL that the user should be redirected to for authorization.
    async fn begin_oauth_flow(
        &self,
        provider: Self::Provider,
    ) -> Result<Self::AuthorizationUrl, Self::OAuth2Error>;

    /// Complete an OAuth2 authorization flow.
    ///
    /// Called when the OAuth2 provider redirects back with an authorization code.
    async fn complete_oauth_flow(&self, code: String) -> Result<Self::Token, Self::OAuth2Error>;
}

// ============================================================================
// Optional Capability: Token Revocation
// ============================================================================

/// Optional trait for authentication schemes that support token/session revocation.
///
/// Schemes implementing this allow users to explicitly invalidate tokens
/// (e.g., during logout, password reset, or account deletion).
#[async_trait]
pub trait SupportsTokenRevocation: AuthenticationScheme {
    /// Errors that can occur during token revocation
    type RevocationError: std::error::Error + Send + Sync + 'static;

    /// Revoke/invalidate a token so it can no longer be used.
    ///
    /// Commonly used for logout functionality.
    async fn revoke_token(&self, token: &Self::Token) -> Result<(), Self::RevocationError>;
}

// ============================================================================
// Optional Capability: Password Reset
// ============================================================================

/// Optional trait for authentication schemes that support password reset flows.
///
/// Only applicable to schemes that use passwords.
#[async_trait]
pub trait SupportsPasswordReset: AuthenticationScheme {
    /// Errors that can occur during password reset
    type PasswordResetError: std::error::Error + Send + Sync + 'static;

    /// Initiate a password reset flow.
    ///
    /// Typically sends a reset link/code to the user's email.
    async fn initiate_password_reset(&self, email: Email) -> Result<(), Self::PasswordResetError>;

    /// Complete a password reset with a new password.
    ///
    /// Called when user provides the reset token and new password.
    async fn complete_password_reset(
        &self,
        reset_token: String,
        new_password: Password,
    ) -> Result<(), Self::PasswordResetError>;
}

// ============================================================================
// Optional Capability: Elevated Tokens
// ============================================================================

/// Optional trait for authentication schemes that support elevated privilege tokens.
///
/// Elevated tokens are short-lived tokens that grant temporary elevated privileges
/// for sensitive operations (e.g., changing passwords, deleting accounts, viewing
/// sensitive data). They require re-authentication even if the user has a valid
/// session token.
///
/// This implements the "sudo" pattern common in security-sensitive applications.
#[async_trait]
pub trait SupportsElevation: AuthenticationScheme {
    /// The type of elevated token (may be same as Token or different)
    type ElevatedToken: Clone + Send + Sync;

    /// The validator for elevated tokens
    type ElevatedValidator: AuthValidator;

    /// Errors that can occur during elevation
    type ElevationError: std::error::Error + Send + Sync + 'static;

    /// Create an elevated token by re-authenticating the user.
    ///
    /// The user must provide their password again, even if they have a valid
    /// session token. This ensures they are present and consenting to the
    /// elevated operation.
    ///
    /// # Arguments
    /// * `email` - User's email (typically from existing auth token)
    /// * `password` - User's password for re-authentication
    ///
    /// # Returns
    /// An elevated token with a shorter expiry time and potentially different claims
    async fn elevate(
        &self,
        email: Email,
        password: Password,
    ) -> Result<Self::ElevatedToken, Self::ElevationError>;

    /// Get the validator for elevated tokens.
    ///
    /// This validator is used to verify elevated tokens on protected routes
    /// that require elevated privileges.
    fn elevated_validator(&self) -> &Self::ElevatedValidator;

    /// Revoke/invalidate an elevated token so it can no longer be used.
    ///
    /// This is typically called during logout to ensure both regular and
    /// elevated tokens are invalidated.
    ///
    /// # Arguments
    /// * `token` - The elevated token to revoke
    ///
    /// # Returns
    /// Ok(()) if revocation succeeded, or an error
    async fn revoke_elevated_token(
        &self,
        token: &Self::ElevatedToken,
    ) -> Result<(), Self::ElevationError>;
}

// ============================================================================
// Optional Capability: Password Change
// ============================================================================

/// Optional trait for authentication schemes that support password changes.
///
/// Only applicable to schemes that use passwords (not OAuth2, API keys, etc.).
/// Password changes are sensitive operations that typically require elevated
/// authentication via the SupportsElevation trait.
#[async_trait]
pub trait SupportsPasswordChange: AuthenticationScheme {
    /// Errors that can occur during password change
    type PasswordChangeError: std::error::Error + Send + Sync + 'static;

    /// Change a user's password.
    ///
    /// This should be called only after verifying elevated authentication.
    /// Routes should require re-authentication before calling this method.
    ///
    /// # Arguments
    /// * `email` - User's email (extracted from elevated token)
    /// * `new_password` - The new password to set
    async fn change_password(
        &self,
        email: Email,
        new_password: Password,
    ) -> Result<(), Self::PasswordChangeError>;
}

// ============================================================================
// Optional Capability: Email Verification
// ============================================================================

/// Optional trait for authentication schemes that require users to verify their email.
///
/// Schemes implementing this can send verification emails after registration and
/// validate verification tokens submitted by the user.  Whether login is blocked
/// for unverified users is the application's responsibility — this trait only
/// exposes the verification flow itself.
#[async_trait]
pub trait RequiresEmailVerification: AuthenticationScheme {
    /// Errors that can occur during email verification
    type EmailVerificationError: std::error::Error + Send + Sync + 'static;

    /// Generate a verification token, persist it, and send the verification email.
    ///
    /// Typically called right after a new user registers.
    async fn initiate_email_verification(
        &self,
        email: Email,
    ) -> Result<(), Self::EmailVerificationError>;

    /// Verify the email by consuming the token from the verification link.
    async fn verify_email(&self, token: String) -> Result<(), Self::EmailVerificationError>;

    /// Returns `true` if the given email address has been verified.
    async fn is_email_verified(
        &self,
        email: &Email,
    ) -> Result<bool, Self::EmailVerificationError>;
}

// ============================================================================
// Optional Capability: Account Deletion
// ============================================================================

/// Optional trait for authentication schemes that support account deletion.
///
/// Account deletion is a sensitive operation that typically requires elevated
/// authentication via the SupportsElevation trait.
#[async_trait]
pub trait SupportsAccountDeletion: AuthenticationScheme {
    /// Errors that can occur during account deletion
    type AccountDeletionError: std::error::Error + Send + Sync + 'static;

    /// Delete a user's account.
    ///
    /// This should be called only after verifying elevated authentication.
    /// Routes should require re-authentication before calling this method.
    ///
    /// # Arguments
    /// * `email` - User's email (extracted from elevated token)
    async fn delete_account(&self, email: Email) -> Result<(), Self::AccountDeletionError>;
}
