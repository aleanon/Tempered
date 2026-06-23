use async_trait::async_trait;
use secrecy::{ExposeSecret, Secret};
use serde::Deserialize;
use tempered_core::{
    AuthRequest, BannedTokenStore, BannedTokenStoreError, Email, EmailClient,
    EmailVerificationStoreError, EmailVerificationToken, EmailVerificationTokenStore,
    HttpAuthenticationScheme, HttpResponseBuilderExt, Password, PasswordResetToken,
    PasswordResetTokenStore, PasswordResetTokenStoreError, RequiresEmailVerification,
    ResponseBuilder, SupportsAccountDeletion, SupportsElevation, SupportsPasswordChange,
    SupportsPasswordReset, TwoFaAttemptId, TwoFaCode, TwoFaCodeStore, TwoFaCodeStoreError,
    TwoFaError, User, UserError, UserStore, UserStoreError, ValidatedUser,
    strategies::authenticator::{
        AuthenticationScheme, LoginOutcome, SupportsRegistration, SupportsTwoFactor,
    },
};
use thiserror::Error;

use crate::auth_validation::local_jwt_validator::{
    JwtAuthConfig, LocalJwtValidator, TokenAuthError, create_auth_cookie, generate_auth_token,
};

// ============================================================================
// JWT Authentication Scheme
// ============================================================================
//
// The scheme is built with a **type-state builder**: `new()` takes only the
// mandatory core (user store + JWT config + banned-token store), and each
// optional capability is opted into with a `supports_*` method that fills a
// generic *slot* (which defaults to `()` = disabled).
//
// Crucially, every optional capability's trait `impl` is bound to its slot
// being a *real* type, so a disabled capability's trait does not exist at all.
// That makes the framework route builders (`auth_service(...).with_2fa(...)`)
// fail to compile unless the matching `supports_*` was called — capability and
// route can never drift apart.

/// JWT-based authentication scheme using password credentials.
///
/// Generic slots (each defaults to `()` = disabled):
/// - `F` — two-factor   ([`TwoFa`],         via [`JwtScheme::supports_2fa`])
/// - `L` — elevation    ([`Elevation`],     via [`JwtScheme::supports_elevation`])
/// - `R` — password reset ([`PasswordReset`], via [`JwtScheme::supports_password_reset`])
/// - `M` — email verify ([`EmailVerify`],   via [`JwtScheme::supports_email_verification`])
#[derive(Clone)]
pub struct JwtScheme<U, B, F = (), L = (), R = (), M = ()> {
    user_store: U,
    banned_token_store: B,
    jwt_validator: LocalJwtValidator<B>,
    jwt_config: JwtAuthConfig,
    two_fa: F,
    elevation: L,
    password_reset: R,
    email_verify: M,
}

// ============================================================================
// Capability slots (the "enabled" states for each optional capability)
// ============================================================================

/// Enabled two-factor slot: a code store plus the email client used to deliver codes.
#[derive(Clone)]
pub struct TwoFa<T, E> {
    store: T,
    email: E,
}

/// Enabled elevation ("sudo") slot: a separate validator/config for short-lived elevated tokens.
#[derive(Clone)]
pub struct Elevation<B> {
    validator: LocalJwtValidator<B>,
    config: JwtAuthConfig,
}

/// Enabled password-reset slot: a reset-token store plus the email client used to deliver links.
#[derive(Clone)]
pub struct PasswordReset<P, E> {
    store: P,
    email: E,
}

/// Enabled email-verification slot: a verification store plus the email client used to deliver links.
#[derive(Clone)]
pub struct EmailVerify<V, E> {
    store: V,
    email: E,
}

// ============================================================================
// Internal slot traits
// ============================================================================
//
// A handful of *core* paths must stay generic over the slots (e.g. `login`
// issues a 2FA challenge; `logout` clears the elevated cookie). Rather than
// duplicating those impls per slot-combination, the slot itself provides the
// behavior through these sealed-ish internal traits — implemented for `()` as
// a no-op/error and for the real slot as the actual behavior. The *public*
// capability traits stay gated to the enabled slot only.

/// Issues the 2FA challenge during `login`. `()` rejects (2FA not configured).
#[async_trait]
trait TwoFaChallenge {
    async fn issue_challenge(&self, email: &Email) -> Result<TwoFaAttemptId, JwtAuthError>;
}

#[async_trait]
impl TwoFaChallenge for () {
    async fn issue_challenge(&self, _email: &Email) -> Result<TwoFaAttemptId, JwtAuthError> {
        // A user requires 2FA but the scheme was built without `supports_2fa`.
        Err(JwtAuthError::TwoFaNotConfigured)
    }
}

#[async_trait]
impl<T, E> TwoFaChallenge for TwoFa<T, E>
where
    T: TwoFaCodeStore + Send + Sync,
    E: EmailClient + Send + Sync,
{
    async fn issue_challenge(&self, email: &Email) -> Result<TwoFaAttemptId, JwtAuthError> {
        let attempt_id = TwoFaAttemptId::new();
        let code = TwoFaCode::new();

        self.store
            .store_code(email.clone(), attempt_id.clone(), code.clone())
            .await?;

        self.email
            .send_email(email, "2FA Code", code.as_str())
            .await
            .map_err(JwtAuthError::EmailError)?;

        Ok(attempt_id)
    }
}

/// Exposes the elevated cookie name (if elevation is enabled) so `logout` can clear it.
trait ElevatedCookieName {
    fn elevated_cookie_name(&self) -> Option<&str>;
}

impl ElevatedCookieName for () {
    fn elevated_cookie_name(&self) -> Option<&str> {
        None
    }
}

impl<B> ElevatedCookieName for Elevation<B> {
    fn elevated_cookie_name(&self) -> Option<&str> {
        Some(&self.config.jwt_cookie_name)
    }
}

// ============================================================================
// Builder: new() + supports_*()
// ============================================================================

impl<U, B> JwtScheme<U, B, (), (), (), ()>
where
    U: UserStore,
    B: BannedTokenStore + Clone,
{
    /// Create the core scheme: password login, logout, and token validation.
    ///
    /// Opt into optional capabilities with the `supports_*` methods.
    pub fn new(user_store: U, jwt_config: JwtAuthConfig, banned_token_store: B) -> Self {
        let jwt_validator = LocalJwtValidator::new(banned_token_store.clone(), jwt_config.clone());

        Self {
            user_store,
            banned_token_store,
            jwt_validator,
            jwt_config,
            two_fa: (),
            elevation: (),
            password_reset: (),
            email_verify: (),
        }
    }
}

impl<U, B, L, R, M> JwtScheme<U, B, (), L, R, M> {
    /// Enable two-factor authentication, lighting up [`SupportsTwoFactor`].
    pub fn supports_2fa<T, E>(self, store: T, email: E) -> JwtScheme<U, B, TwoFa<T, E>, L, R, M> {
        JwtScheme {
            user_store: self.user_store,
            banned_token_store: self.banned_token_store,
            jwt_validator: self.jwt_validator,
            jwt_config: self.jwt_config,
            two_fa: TwoFa { store, email },
            elevation: self.elevation,
            password_reset: self.password_reset,
            email_verify: self.email_verify,
        }
    }
}

impl<U, B, F, R, M> JwtScheme<U, B, F, (), R, M>
where
    B: Clone,
{
    /// Enable elevated ("sudo") tokens, lighting up [`SupportsElevation`] and
    /// [`tempered_core::HttpElevationScheme`].
    pub fn supports_elevation(
        self,
        elevated_banned_token_store: B,
        elevated_jwt_config: JwtAuthConfig,
    ) -> JwtScheme<U, B, F, Elevation<B>, R, M> {
        let validator =
            LocalJwtValidator::new(elevated_banned_token_store, elevated_jwt_config.clone());

        JwtScheme {
            user_store: self.user_store,
            banned_token_store: self.banned_token_store,
            jwt_validator: self.jwt_validator,
            jwt_config: self.jwt_config,
            two_fa: self.two_fa,
            elevation: Elevation {
                validator,
                config: elevated_jwt_config,
            },
            password_reset: self.password_reset,
            email_verify: self.email_verify,
        }
    }
}

impl<U, B, F, L, M> JwtScheme<U, B, F, L, (), M> {
    /// Enable password reset, lighting up [`SupportsPasswordReset`].
    pub fn supports_password_reset<P, E>(
        self,
        store: P,
        email: E,
    ) -> JwtScheme<U, B, F, L, PasswordReset<P, E>, M> {
        JwtScheme {
            user_store: self.user_store,
            banned_token_store: self.banned_token_store,
            jwt_validator: self.jwt_validator,
            jwt_config: self.jwt_config,
            two_fa: self.two_fa,
            elevation: self.elevation,
            password_reset: PasswordReset { store, email },
            email_verify: self.email_verify,
        }
    }
}

impl<U, B, F, L, R> JwtScheme<U, B, F, L, R, ()> {
    /// Enable email verification, lighting up [`RequiresEmailVerification`].
    pub fn supports_email_verification<V, E>(
        self,
        store: V,
        email: E,
    ) -> JwtScheme<U, B, F, L, R, EmailVerify<V, E>> {
        JwtScheme {
            user_store: self.user_store,
            banned_token_store: self.banned_token_store,
            jwt_validator: self.jwt_validator,
            jwt_config: self.jwt_config,
            two_fa: self.two_fa,
            elevation: self.elevation,
            password_reset: self.password_reset,
            email_verify: EmailVerify { store, email },
        }
    }
}

impl<U, B, F, L, R, M> JwtScheme<U, B, F, L, R, M> {
    /// Finalizer for readability; the scheme is already usable after the last
    /// `supports_*`. Returns `self` unchanged.
    pub fn build(self) -> Self {
        self
    }

    pub fn cookie_name(&self) -> &str {
        &self.jwt_config.jwt_cookie_name
    }

    pub fn user_store(&self) -> &U {
        &self.user_store
    }

    fn generate_token(&self, email: &Email) -> Result<JwtToken, TokenAuthError> {
        let token_string = generate_auth_token(
            email,
            self.jwt_config.token_ttl_in_seconds,
            self.jwt_config.jwt_secret.expose_secret().as_bytes(),
        )?;

        Ok(JwtToken(token_string))
    }
}

// ============================================================================
// HTTP Authentication Scheme - Framework-agnostic HTTP-level token delivery
// ============================================================================

#[async_trait]
impl<U, B, F, L, R, M> HttpAuthenticationScheme for JwtScheme<U, B, F, L, R, M>
where
    U: UserStore + Clone + 'static,
    B: BannedTokenStore + Clone + Send + Sync + 'static,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: ElevatedCookieName + Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
{
    fn create_login_response<RB: ResponseBuilder>(
        &self,
        builder: RB,
        outcome: LoginOutcome<Self::Token>,
    ) -> Result<RB::Response, tempered_core::ResponseBuilderError> {
        match outcome {
            LoginOutcome::Success(token) => {
                // For JWT, we deliver the token via HTTP-only cookie
                let cookie =
                    create_auth_cookie(token.into_string(), &self.jwt_config.jwt_cookie_name);

                builder
                    .status(200)
                    .cookie(&cookie.to_string())
                    .json_body(serde_json::json!({
                        "status": "success",
                        "message": "Login successful"
                    }))
                    .build()
            }
            LoginOutcome::Requires2Fa {
                email: _,
                attempt_id,
            } => {
                // User needs to provide 2FA code
                builder
                    .status(206) // 206 Partial Content indicates 2FA required
                    .json_body(serde_json::json!({
                        "status": "requires_2fa",
                        "message": "2FA required",
                        "loginAttemptId": attempt_id.to_string()
                    }))
                    .build()
            }
        }
    }

    fn create_logout_response<RB: ResponseBuilder>(
        &self,
        builder: RB,
        cookie_name: Option<String>,
    ) -> Result<RB::Response, tempered_core::ResponseBuilderError> {
        let cookie_name = cookie_name.unwrap_or_else(|| self.jwt_config.jwt_cookie_name.clone());

        // Clear the primary auth cookie by expiring it immediately.
        let clear_cookie = format!(
            "{}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
            cookie_name
        );
        let builder = builder.status(200).cookie(&clear_cookie);

        // Also clear the elevated cookie, but only if elevation is enabled —
        // otherwise no elevated cookie could ever have been set.
        let builder = match self.elevation.elevated_cookie_name() {
            Some(name) => builder.cookie(&format!(
                "{}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
                name
            )),
            None => builder,
        };

        builder
            .json_body(serde_json::json!({
                "message": "Logged out successfully"
            }))
            .build()
    }

    fn extract_token_from_request<Req: AuthRequest>(&self, req: &Req) -> Option<Self::Token> {
        req.cookie(&self.jwt_config.jwt_cookie_name)
            .map(|token_str| JwtToken(token_str.to_string()))
    }
}

// ============================================================================
// Core Trait: AuthenticationScheme
// ============================================================================

#[async_trait]
impl<U, B, F, L, R, M> AuthenticationScheme for JwtScheme<U, B, F, L, R, M>
where
    U: UserStore + Clone + 'static,
    B: BannedTokenStore + Clone + Send + Sync + 'static,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
{
    type Token = JwtToken;
    type Validator = LocalJwtValidator<B>;
    type LogoutOutput = String;
    type Credentials = PasswordCredentials;
    type AuthError = JwtAuthError;

    #[tracing::instrument(name = "JwtScheme::login", skip(self, credentials))]
    async fn login(
        &self,
        credentials: Self::Credentials,
    ) -> Result<LoginOutcome<Self::Token>, Self::AuthError> {
        // Parse domain types from credentials
        let email = Email::try_from(credentials.email)?;
        let password = Password::try_from(credentials.password)?;

        // Authenticate user credentials
        let validated_user = self.user_store.authenticate_user(&email, &password).await?;

        match validated_user {
            ValidatedUser::Requires2Fa(email) => {
                // Delegate to the 2FA slot: issues + delivers the challenge, or
                // errors if the scheme was built without `supports_2fa`.
                let attempt_id = self.two_fa.issue_challenge(&email).await?;

                Ok(LoginOutcome::Requires2Fa {
                    email,
                    attempt_id,
                })
            }
            ValidatedUser::No2Fa(email) => {
                // User authenticated successfully without 2FA
                let token = self.generate_token(&email)?;
                Ok(LoginOutcome::Success(token))
            }
        }
    }

    async fn logout(&self, token: &Self::Token) -> Result<Self::LogoutOutput, Self::AuthError> {
        self.banned_token_store.ban_token(token.0.clone()).await?;

        Ok(self.jwt_config.jwt_cookie_name.clone())
    }

    fn validator(&self) -> &Self::Validator {
        &self.jwt_validator
    }
}

// ============================================================================
// Optional Capability: Registration (needs only the user store → always on)
// ============================================================================

#[async_trait]
impl<U, B, F, L, R, M> SupportsRegistration for JwtScheme<U, B, F, L, R, M>
where
    U: UserStore + Clone + 'static,
    B: BannedTokenStore + Clone + Send + Sync + 'static,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
{
    type RegistrationData = RegistrationData;
    type RegistrationError = JwtAuthError;

    #[tracing::instrument(name = "JwtScheme::register", skip(self, password))]
    async fn register(
        &self,
        email: Email,
        password: Password,
        data: Self::RegistrationData,
    ) -> Result<(), Self::RegistrationError> {
        // Create new user
        let user = User::new(email, password, data.requires_2fa);

        // Add user to store
        self.user_store.add_user(user).await?;

        Ok(())
    }
}

// ============================================================================
// Optional Capability: Two-Factor Authentication (gated on the `TwoFa` slot)
// ============================================================================

#[async_trait]
impl<U, B, T, E, L, R, M> SupportsTwoFactor for JwtScheme<U, B, TwoFa<T, E>, L, R, M>
where
    U: UserStore + Clone + 'static,
    B: BannedTokenStore + Clone + Send + Sync + 'static,
    T: TwoFaCodeStore + Clone + Send + Sync + 'static,
    E: EmailClient + Clone + Send + Sync + 'static,
    L: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
{
    type TwoFactorError = JwtAuthError;

    #[tracing::instrument(name = "JwtScheme::verify_2fa", skip(self, code))]
    async fn verify_2fa(
        &self,
        email: Email,
        attempt_id: TwoFaAttemptId,
        code: TwoFaCode,
    ) -> Result<Self::Token, Self::TwoFactorError> {
        // Validate the 2FA code
        self.two_fa
            .store
            .validate(&email, &attempt_id, &code)
            .await?;

        // Delete the used 2FA code
        self.two_fa.store.delete(&email).await?;

        // Generate token for verified user
        let token = self.generate_token(&email)?;
        Ok(token)
    }
}

// ============================================================================
// Domain Types
// ============================================================================

/// JWT token wrapper type
#[derive(Debug, Clone)]
pub struct JwtToken(pub String);

impl JwtToken {
    /// Get the raw token string
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert into the inner string
    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<String> for JwtToken {
    fn from(s: String) -> Self {
        JwtToken(s)
    }
}

/// Credentials for password-based login
#[derive(Debug, Deserialize)]
pub struct PasswordCredentials {
    pub email: Secret<String>,
    pub password: Secret<String>,
}

/// Additional data needed for user registration
#[derive(Debug, Deserialize)]
pub struct RegistrationData {
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, Error)]
pub enum JwtAuthError {
    #[error("User error: {0}")]
    UserError(#[from] UserError),

    #[error("Two-factor authentication error: {0}")]
    TwoFaError(#[from] TwoFaError),

    #[error("Two-factor authentication is required but not configured for this scheme")]
    TwoFaNotConfigured,

    #[error("Token error: {0}")]
    TokenError(#[from] TokenAuthError),

    #[error("User store error: {0}")]
    UserStoreError(#[from] UserStoreError),

    #[error("2FA code store error: {0}")]
    TwoFaCodeStoreError(#[from] TwoFaCodeStoreError),

    #[error("Failed to send email: {0}")]
    EmailError(String),

    #[error("Failed to ban JWT token: {0}")]
    BanTokenStoreError(#[from] BannedTokenStoreError),

    #[error("Invalid or expired password reset token")]
    InvalidResetToken,

    #[error("Password reset token store error: {0}")]
    PasswordResetTokenStoreError(#[from] PasswordResetTokenStoreError),

    #[error("Invalid or expired email verification token")]
    InvalidVerificationToken,

    #[error("Email verification store error: {0}")]
    EmailVerificationStoreError(#[from] EmailVerificationStoreError),
}

impl tempered_core::IntoStatusMessage for JwtAuthError {
    fn into_status_message(self) -> (http::StatusCode, String) {
        match self {
            // Validation errors -> 400 BAD_REQUEST
            JwtAuthError::UserError(e) => (http::StatusCode::BAD_REQUEST, e.to_string()),

            // Authentication failures -> 401 UNAUTHORIZED
            JwtAuthError::UserStoreError(UserStoreError::UserNotFound) => {
                (http::StatusCode::UNAUTHORIZED, "User not found".to_string())
            }
            JwtAuthError::UserStoreError(UserStoreError::IncorrectPassword) => (
                http::StatusCode::UNAUTHORIZED,
                "Incorrect password".to_string(),
            ),

            // Conflict errors -> 409 CONFLICT
            JwtAuthError::UserStoreError(UserStoreError::UserAlreadyExists) => (
                http::StatusCode::CONFLICT,
                "User already exists".to_string(),
            ),

            // 2FA errors -> 401 UNAUTHORIZED
            JwtAuthError::TwoFaError(e) => (http::StatusCode::UNAUTHORIZED, e.to_string()),
            JwtAuthError::TwoFaCodeStoreError(e) => (
                http::StatusCode::UNAUTHORIZED,
                format!("2FA code store error: {}", e),
            ),

            // Misconfiguration: a 2FA user on a scheme without 2FA -> 500
            JwtAuthError::TwoFaNotConfigured => (
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "Two-factor authentication is required but not configured".to_string(),
            ),

            // Token errors -> use their own mapping
            JwtAuthError::TokenError(e) => e.into_status_message(),

            // Invalid reset token -> 400 BAD_REQUEST (token expired or never existed)
            JwtAuthError::InvalidResetToken => (
                http::StatusCode::BAD_REQUEST,
                "Invalid or expired password reset token".to_string(),
            ),

            // Server errors -> 500 INTERNAL_SERVER_ERROR
            JwtAuthError::UserStoreError(e) => (
                http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("User store error: {}", e),
            ),
            JwtAuthError::EmailError(e) => (http::StatusCode::INTERNAL_SERVER_ERROR, e),
            JwtAuthError::BanTokenStoreError(e) => (
                http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Token store error: {}", e),
            ),
            JwtAuthError::PasswordResetTokenStoreError(e) => (
                http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Reset token store error: {}", e),
            ),

            JwtAuthError::InvalidVerificationToken => (
                http::StatusCode::BAD_REQUEST,
                "Invalid or expired email verification token".to_string(),
            ),
            JwtAuthError::EmailVerificationStoreError(e) => (
                http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Email verification store error: {}", e),
            ),
        }
    }
}

// ============================================================================
// Optional Capability: Elevated Tokens (Sudo Pattern) — gated on `Elevation`
// ============================================================================

/// Elevated JWT token with shorter TTL for sensitive operations
#[derive(Debug, Clone)]
pub struct ElevatedJwtToken(pub String);

impl ElevatedJwtToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

#[async_trait]
impl<U, B, F, R, M> SupportsElevation for JwtScheme<U, B, F, Elevation<B>, R, M>
where
    U: UserStore + Clone + 'static,
    B: BannedTokenStore + Clone + Send + Sync + 'static,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
{
    type ElevatedToken = ElevatedJwtToken;
    type ElevatedValidator = LocalJwtValidator<B>;
    type ElevationError = JwtAuthError;

    #[tracing::instrument(name = "JwtScheme::elevate", skip(self, password))]
    async fn elevate(
        &self,
        email: Email,
        password: Password,
    ) -> Result<Self::ElevatedToken, Self::ElevationError> {
        // Re-authenticate the user with their password
        self.user_store.authenticate_user(&email, &password).await?;

        // Generate an elevated token using the elevated config (with shorter TTL)
        let token_string = generate_auth_token(
            &email,
            self.elevation.config.token_ttl_in_seconds,
            self.elevation.config.jwt_secret.expose_secret().as_bytes(),
        )?;

        Ok(ElevatedJwtToken(token_string))
    }

    fn elevated_validator(&self) -> &Self::ElevatedValidator {
        &self.elevation.validator
    }

    async fn revoke_elevated_token(
        &self,
        token: &Self::ElevatedToken,
    ) -> Result<(), Self::ElevationError> {
        self.elevation
            .validator
            .banned_token_store
            .ban_token(token.0.clone())
            .await
            .map_err(JwtAuthError::BanTokenStoreError)?;
        Ok(())
    }
}

// ============================================================================
// HTTP Elevation Scheme - Framework-agnostic elevated token delivery
// ============================================================================

impl<U, B, F, R, M> tempered_core::HttpElevationScheme for JwtScheme<U, B, F, Elevation<B>, R, M>
where
    U: UserStore + Clone + 'static,
    B: BannedTokenStore + Clone + Send + Sync + 'static,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
{
    fn create_elevation_response<RB: ResponseBuilder>(
        &self,
        builder: RB,
        elevated_token: Self::ElevatedToken,
    ) -> Result<RB::Response, tempered_core::ResponseBuilderError> {
        // Use the elevated JWT config's cookie name
        let cookie = create_auth_cookie(
            elevated_token.into_string(),
            &self.elevation.config.jwt_cookie_name,
        );

        builder
            .status(200)
            .cookie(&cookie.to_string())
            .json_body(serde_json::json!({
                "status": "elevated",
                "message": "Elevation successful"
            }))
            .build()
    }

    fn extract_elevated_token_from_request<Req: AuthRequest>(
        &self,
        req: &Req,
    ) -> Option<Self::ElevatedToken> {
        req.cookie(&self.elevation.config.jwt_cookie_name)
            .map(|token_str| ElevatedJwtToken(token_str.to_string()))
    }
}

// ============================================================================
// Optional Capability: Password Change (needs only the user store → always on)
// ============================================================================

#[async_trait]
impl<U, B, F, L, R, M> SupportsPasswordChange for JwtScheme<U, B, F, L, R, M>
where
    U: UserStore + Clone + 'static,
    B: BannedTokenStore + Clone + Send + Sync + 'static,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
{
    type PasswordChangeError = JwtAuthError;

    #[tracing::instrument(name = "JwtScheme::change_password", skip(self, new_password))]
    async fn change_password(
        &self,
        email: Email,
        new_password: Password,
    ) -> Result<(), Self::PasswordChangeError> {
        // Update the user's password in the user store
        self.user_store
            .set_new_password(&email, new_password)
            .await?;

        Ok(())
    }
}

// ============================================================================
// Optional Capability: Account Deletion (needs only the user store → always on)
// ============================================================================

#[async_trait]
impl<U, B, F, L, R, M> SupportsAccountDeletion for JwtScheme<U, B, F, L, R, M>
where
    U: UserStore + Clone + 'static,
    B: BannedTokenStore + Clone + Send + Sync + 'static,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
{
    type AccountDeletionError = JwtAuthError;

    #[tracing::instrument(name = "JwtScheme::delete_account", skip(self))]
    async fn delete_account(&self, email: Email) -> Result<(), Self::AccountDeletionError> {
        // Delete the user from the user store
        self.user_store.delete_user(&email).await?;

        Ok(())
    }
}

// ============================================================================
// Optional Capability: Password Reset (gated on the `PasswordReset` slot)
// ============================================================================

#[async_trait]
impl<U, B, F, L, P, E, M> SupportsPasswordReset for JwtScheme<U, B, F, L, PasswordReset<P, E>, M>
where
    U: UserStore + Clone + 'static,
    B: BannedTokenStore + Clone + Send + Sync + 'static,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: Clone + Send + Sync + 'static,
    P: PasswordResetTokenStore + Clone + Send + Sync + 'static,
    E: EmailClient + Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
{
    type PasswordResetError = JwtAuthError;

    #[tracing::instrument(name = "JwtScheme::initiate_password_reset", skip(self))]
    async fn initiate_password_reset(&self, email: Email) -> Result<(), Self::PasswordResetError> {
        // Check that the user exists; if not, return Ok silently to prevent email enumeration.
        if self.user_store.get_user(&email).await.is_err() {
            return Ok(());
        }

        let token = PasswordResetToken::new();

        self.password_reset
            .store
            .store_token(token.clone(), email.clone())
            .await?;

        self.password_reset
            .email
            .send_email(&email, "Password Reset", &token.to_string())
            .await
            .map_err(JwtAuthError::EmailError)?;

        Ok(())
    }

    #[tracing::instrument(name = "JwtScheme::complete_password_reset", skip(self, new_password))]
    async fn complete_password_reset(
        &self,
        reset_token: String,
        new_password: Password,
    ) -> Result<(), Self::PasswordResetError> {
        let token =
            PasswordResetToken::parse(&reset_token).ok_or(JwtAuthError::InvalidResetToken)?;

        let email = self
            .password_reset
            .store
            .get_email_for_token(&token)
            .await
            .map_err(|_| JwtAuthError::InvalidResetToken)?;

        self.user_store
            .set_new_password(&email, new_password)
            .await?;

        // Best-effort deletion: token is already consumed, so ignore delete errors.
        let _ = self.password_reset.store.delete_token(&token).await;

        Ok(())
    }
}

// ============================================================================
// Optional Capability: Email Verification (gated on the `EmailVerify` slot)
// ============================================================================

#[async_trait]
impl<U, B, F, L, R, V, E> RequiresEmailVerification
    for JwtScheme<U, B, F, L, R, EmailVerify<V, E>>
where
    U: UserStore + Clone + 'static,
    B: BannedTokenStore + Clone + Send + Sync + 'static,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    V: EmailVerificationTokenStore + Clone + Send + Sync + 'static,
    E: EmailClient + Clone + Send + Sync + 'static,
{
    type EmailVerificationError = JwtAuthError;

    #[tracing::instrument(name = "JwtScheme::initiate_email_verification", skip(self))]
    async fn initiate_email_verification(
        &self,
        email: Email,
    ) -> Result<(), Self::EmailVerificationError> {
        let token = EmailVerificationToken::new();

        self.email_verify
            .store
            .store_pending_verification(token.clone(), email.clone())
            .await?;

        self.email_verify
            .email
            .send_email(&email, "Verify your email", &token.to_string())
            .await
            .map_err(JwtAuthError::EmailError)?;

        Ok(())
    }

    #[tracing::instrument(name = "JwtScheme::verify_email", skip(self))]
    async fn verify_email(&self, token: String) -> Result<(), Self::EmailVerificationError> {
        let token = EmailVerificationToken::parse(&token)
            .ok_or(JwtAuthError::InvalidVerificationToken)?;

        let email = self
            .email_verify
            .store
            .consume_token(&token)
            .await
            .map_err(|_| JwtAuthError::InvalidVerificationToken)?;

        self.email_verify.store.mark_verified(&email).await?;

        Ok(())
    }

    #[tracing::instrument(name = "JwtScheme::is_email_verified", skip(self))]
    async fn is_email_verified(
        &self,
        email: &Email,
    ) -> Result<bool, Self::EmailVerificationError> {
        Ok(self.email_verify.store.is_verified(email).await?)
    }
}
