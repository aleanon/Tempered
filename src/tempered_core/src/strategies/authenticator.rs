use async_trait::async_trait;
use serde::Deserialize;

use crate::{
    domain::{
        api_key::ApiKeyId,
        email::Email,
        passkey::{CeremonyId, PasskeyCeremony},
        password::Password,
        two_fa_attempt_id::TwoFaAttemptId,
        two_fa_code::TwoFaCode,
    },
    ports::repositories::ApiKeyMetadata,
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

/// The result of beginning an OAuth2 / OIDC authorization-code flow.
///
/// `state` is the anti-CSRF nonce that the delivery layer must **bind to the
/// initiating browser** — set it as an `HttpOnly; Secure; SameSite=Lax` cookie
/// on the redirect response, then pass that cookie's value back to
/// [`SupportsOAuth2::complete_oauth`] as `cookie_state`. Without this binding the
/// server-side state store alone would let any browser complete any pending flow
/// (login CSRF).
pub struct AuthorizationRequest {
    /// The provider URL to redirect the user to for authorization.
    pub authorize_url: String,
    /// The anti-CSRF state to bind to the initiating browser.
    pub state: String,
}

/// Optional trait for authentication schemes that can authenticate users via an
/// OAuth2 / OIDC provider (Google, GitHub, …).
///
/// Unlike credential login, OAuth is a two-leg redirect flow. The provider
/// verifies the user's identity and yields a verified [`Email`]; from there an
/// OAuth login follows the same rules as any other login:
///
/// - **No local account for that email:** one is created (the provider has
///   verified the address), and the user is logged in.
/// - **An account exists:** it is a normal login to that account. If the
///   account requires two-factor authentication, the second factor is still
///   required — the provider replaces the password, not the second factor.
///
/// On success the scheme issues its **own primary
/// [`Token`](AuthenticationScheme::Token)**, so a completed OAuth login is
/// indistinguishable from any other.
#[async_trait]
pub trait SupportsOAuth2: AuthenticationScheme {
    /// Errors that can occur during the OAuth flow.
    type OAuth2Error: std::error::Error + Send + Sync + 'static;

    /// Leg 1: begin an authorization-code flow for `provider`.
    ///
    /// Returns the provider authorize URL plus the anti-CSRF `state` the delivery
    /// layer must bind to the initiating browser (see [`AuthorizationRequest`]).
    async fn begin_oauth(&self, provider: &str) -> Result<AuthorizationRequest, Self::OAuth2Error>;

    /// Leg 2: complete the callback and log the user in.
    ///
    /// Validates `state`, exchanges `code`, verifies the provider identity,
    /// creates the local account if there is none, and then returns the same
    /// [`LoginOutcome`] a password login would: a
    /// [`Token`](AuthenticationScheme::Token), or a pending 2FA challenge when
    /// the account requires a second factor.
    ///
    /// `query_state` is the `state` the provider echoed on the callback;
    /// `cookie_state` is the value previously bound to the browser. The two must
    /// match, proving the same browser that began the flow is completing it.
    async fn complete_oauth(
        &self,
        provider: &str,
        code: &str,
        query_state: &str,
        cookie_state: &str,
    ) -> Result<LoginOutcome<Self::Token>, Self::OAuth2Error>;
}

// ============================================================================
// Optional Capability: Passkeys (WebAuthn)
// ============================================================================

/// Optional trait for authentication schemes that can authenticate users with
/// passkeys (WebAuthn).
///
/// Each ceremony is two legs: a `start_*` that returns a [`PasskeyCeremony`] —
/// the options the browser passes to `navigator.credentials` plus a
/// [`CeremonyId`] — and a `finish_*` that takes that id back with the
/// authenticator's response and verifies it. Registration *enrolls* a credential for an
/// **already authenticated** user: both registration legs take the email of the
/// logged-in caller, and a delivery layer must source it from the validated
/// session, never from the request body — otherwise anyone could enroll their
/// own authenticator on someone else's account. Authentication verifies an assertion and — like
/// [`SupportsOAuth2::complete_oauth`] — issues this scheme's **primary
/// [`Token`](AuthenticationScheme::Token)**, so a passkey login yields the same
/// session as any other.
///
/// The `serde_json::Value` options/response payloads are passed through verbatim
/// to the underlying WebAuthn verifier; this trait does not interpret them.
#[async_trait]
pub trait SupportsPasskeys: AuthenticationScheme {
    /// Errors that can occur during a passkey ceremony.
    type PasskeyError: std::error::Error + Send + Sync + 'static;

    /// Registration leg 1: issue creation options for the authenticated user
    /// `email`.
    async fn start_passkey_registration(
        &self,
        email: Email,
    ) -> Result<PasskeyCeremony, Self::PasskeyError>;

    /// Registration leg 2: verify the attestation and enroll the credential.
    ///
    /// `email` is the authenticated user; it must match the user who started
    /// the ceremony identified by `ceremony_id`.
    async fn finish_passkey_registration(
        &self,
        email: Email,
        ceremony_id: CeremonyId,
        response: serde_json::Value,
    ) -> Result<(), Self::PasskeyError>;

    /// Authentication leg 1: issue request options. `email = None` runs a
    /// usernameless (discoverable-credential) ceremony.
    async fn start_passkey_authentication(
        &self,
        email: Option<Email>,
    ) -> Result<PasskeyCeremony, Self::PasskeyError>;

    /// Authentication leg 2: verify the assertion and issue the primary token.
    async fn finish_passkey_authentication(
        &self,
        ceremony_id: CeremonyId,
        response: serde_json::Value,
    ) -> Result<Self::Token, Self::PasskeyError>;
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

    /// Verify `email` by consuming the token from the verification link.
    ///
    /// `email` MUST be the logged-in user's address, never a value from the
    /// request. The token proves control of the inbox; the login proves the
    /// account. Both are needed: with a public link, whoever signed up with
    /// someone else's address could get the real owner to click it, and the
    /// account (with the signer-up's password) would count as proven. A
    /// token sent to another address is rejected, and burned.
    async fn verify_email(
        &self,
        email: &Email,
        token: String,
    ) -> Result<(), Self::EmailVerificationError>;

    /// Returns `true` if the given email address has been verified.
    async fn is_email_verified(&self, email: &Email) -> Result<bool, Self::EmailVerificationError>;
}

// ============================================================================
// Optional Capability: API Key Issuance
// ============================================================================

/// Optional trait for schemes that can issue, revoke and list API keys.
///
/// API keys are *issued* to an already-identified owner (not "logged into"),
/// then presented on each request via a header and checked by the scheme's
/// validator. Issuance/revocation are management operations that a delivery
/// layer typically exposes behind an authenticated (or elevated) route.
#[async_trait]
pub trait SupportsApiKeyIssuance: AuthenticationScheme {
    /// Errors that can occur during issuance/revocation/listing.
    type IssuanceError: std::error::Error + Send + Sync + 'static;

    /// Issue a new key for `owner` with the given scopes.
    ///
    /// Returns the key id and the **plaintext** key, which must be shown to the
    /// caller exactly once and is never recoverable afterwards.
    async fn issue_api_key(
        &self,
        owner: Email,
        scopes: Vec<String>,
    ) -> Result<(ApiKeyId, String), Self::IssuanceError>;

    /// Revoke a previously-issued key.
    async fn revoke_api_key(&self, id: &ApiKeyId) -> Result<(), Self::IssuanceError>;

    /// List non-secret metadata for all of a user's keys.
    async fn list_api_keys(
        &self,
        owner: &Email,
    ) -> Result<Vec<ApiKeyMetadata>, Self::IssuanceError>;
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
