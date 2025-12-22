use async_trait::async_trait;
use secrecy::{ExposeSecret, Secret};
use serde::Deserialize;
use tempered_core::{
    AuthRequest, AuthResponseBuilder, BannedTokenStore, BannedTokenStoreError, Email, EmailClient,
    HttpAuthenticationScheme, Password, TwoFaAttemptId, TwoFaCode, TwoFaCodeStore,
    TwoFaCodeStoreError, TwoFaError, User, UserError, UserStore, UserStoreError, ValidatedUser,
    strategies::authenticator::{
        AuthenticationScheme, LoginOutcome, SupportsRegistration, SupportsTokenRevocation,
        SupportsTwoFactor,
    },
};
use thiserror::Error;

use crate::auth_validation::local_jwt_validator::{
    JwtAuthConfig, LocalJwtValidator, TokenAuthError, create_auth_cookie, generate_auth_token,
};

// ============================================================================
// JWT Authentication Scheme
// ============================================================================

/// JWT-based authentication scheme using password credentials.
///
/// This scheme:
/// - Supports user registration with email/password
/// - Supports password-based login
/// - Supports optional 2FA via TOTP/email codes
/// - Issues JWT tokens stored in HTTP-only cookies
/// - Validates JWT signatures and checks banned token list
#[derive(Clone)]
pub struct JwtScheme<U, T, E, B> {
    user_store: U,
    two_fa_code_store: T,
    email_client: E,
    banned_token_store: B,
    jwt_validator: LocalJwtValidator<B>,
    jwt_config: JwtAuthConfig,
    elevated_jwt_validator: LocalJwtValidator<B>,
    elevated_jwt_config: JwtAuthConfig,
}

impl<U, T, E, B> JwtScheme<U, T, E, B>
where
    U: UserStore,
    T: TwoFaCodeStore,
    E: EmailClient,
    B: Clone,
{
    pub fn new(
        user_store: U,
        two_fa_code_store: T,
        email_client: E,
        banned_token_store: B,
        config: JwtAuthConfig,
        elevated_banned_token_store: B,
        elevated_jwt_config: JwtAuthConfig,
    ) -> Self {
        let validator = LocalJwtValidator::new(banned_token_store.clone(), config.clone());
        let elevated_validator = LocalJwtValidator::new(
            elevated_banned_token_store.clone(),
            elevated_jwt_config.clone(),
        );

        Self {
            user_store,
            two_fa_code_store,
            email_client,
            banned_token_store,
            jwt_validator: validator,
            jwt_config: config,
            elevated_jwt_validator: elevated_validator,
            elevated_jwt_config: elevated_jwt_config,
        }
    }

    pub fn cookie_name(&self) -> &str {
        &self.jwt_config.jwt_cookie_name
    }

    /// Get a reference to the user store
    pub fn user_store(&self) -> &U {
        &self.user_store
    }

    /// Internal helper to generate a JWT token for an authenticated user
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
impl<U, T, E, B> HttpAuthenticationScheme for JwtScheme<U, T, E, B>
where
    U: UserStore + Clone + 'static,
    T: TwoFaCodeStore + Clone + 'static,
    E: EmailClient + Clone + 'static,
    B: BannedTokenStore + Clone + Send + Sync + 'static,
{
    fn create_login_response<RB: AuthResponseBuilder>(
        &self,
        builder: RB,
        outcome: LoginOutcome<Self::Token>,
    ) -> RB::Response {
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

    fn create_logout_response<RB: AuthResponseBuilder>(
        &self,
        builder: RB,
        cookie_name: Option<String>,
    ) -> RB::Response {
        let cookie_name = cookie_name.unwrap_or_else(|| self.jwt_config.jwt_cookie_name.clone());

        // Create a cookie that expires immediately to clear it
        let clear_cookie = format!(
            "{}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
            cookie_name
        );

        builder
            .status(200)
            .cookie(&clear_cookie)
            .json_body(serde_json::json!({
                "message": "Logged out successfully"
            }))
            .build()
    }

    fn extract_token_from_request<R: AuthRequest>(&self, req: &R) -> Option<Self::Token> {
        // For JWT scheme, we extract the token from the cookie
        // Zero-cost: just calls req.cookie() which delegates to framework
        req.cookie(&self.jwt_config.jwt_cookie_name)
            .map(|token_str| JwtToken(token_str.to_string()))
    }
}

// ============================================================================
// Core Trait: AuthenticationScheme
// ============================================================================

#[async_trait]
impl<U, T, E, B> AuthenticationScheme for JwtScheme<U, T, E, B>
where
    U: UserStore + Clone + 'static,
    T: TwoFaCodeStore + Clone + 'static,
    E: EmailClient + Clone + 'static,
    B: BannedTokenStore + Clone + Send + Sync + 'static,
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
                // Handle 2FA required scenario
                let login_attempt_id = TwoFaAttemptId::new();
                let code = TwoFaCode::new();

                // Store the 2FA code
                self.two_fa_code_store
                    .store_code(email.clone(), login_attempt_id.clone(), code.clone())
                    .await?;

                // Send the 2FA code via email
                self.email_client
                    .send_email(&email, "2FA Code", code.as_str())
                    .await
                    .map_err(JwtAuthError::EmailError)?;

                Ok(LoginOutcome::Requires2Fa {
                    email,
                    attempt_id: login_attempt_id,
                })
            }
            ValidatedUser::No2Fa(email) => {
                // User authenticated successfully without 2FA
                let token = self.generate_token(&email)?;
                Ok(LoginOutcome::Success(token))
            }
        }
    }

    async fn logout(&self, token: Self::Token) -> Result<Self::LogoutOutput, Self::AuthError> {
        self.banned_token_store.ban_token(token.0).await?;

        Ok(self.jwt_config.jwt_cookie_name.clone())
    }

    fn validator(&self) -> &Self::Validator {
        &self.jwt_validator
    }
}

// ============================================================================
// Optional Capability: Registration
// ============================================================================

#[async_trait]
impl<U, T, E, B> SupportsRegistration for JwtScheme<U, T, E, B>
where
    U: UserStore + Clone + 'static,
    T: TwoFaCodeStore + Clone + 'static,
    E: EmailClient + Clone + 'static,
    B: BannedTokenStore + Clone + Send + Sync + 'static,
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
// Optional Capability: Two-Factor Authentication
// ============================================================================

#[async_trait]
impl<U, T, E, B> SupportsTwoFactor for JwtScheme<U, T, E, B>
where
    U: UserStore + Clone + 'static,
    T: TwoFaCodeStore + Clone + 'static,
    E: EmailClient + Clone + 'static,
    B: BannedTokenStore + Clone + Send + Sync + 'static,
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
        self.two_fa_code_store
            .validate(&email, &attempt_id, &code)
            .await?;

        // Delete the used 2FA code
        self.two_fa_code_store.delete(&email).await?;

        // Generate token for verified user
        let token = self.generate_token(&email)?;
        Ok(token)
    }
}

// ============================================================================
// Optional Capability: Token Revocation (Logout)
// ============================================================================

#[async_trait]
impl<U, T, E, B> SupportsTokenRevocation for JwtScheme<U, T, E, B>
where
    U: UserStore + Clone + 'static,
    T: TwoFaCodeStore + Clone + 'static,
    E: EmailClient + Clone + 'static,
    B: BannedTokenStore + Clone + Send + Sync + 'static,
{
    type RevocationError = JwtAuthError;

    #[tracing::instrument(name = "JwtScheme::revoke_token", skip(self, token))]
    async fn revoke_token(&self, token: &Self::Token) -> Result<(), Self::RevocationError> {
        // Add the token to the banned token store
        // This prevents it from being used for future requests
        self.banned_token_store
            .ban_token(token.as_str().to_string())
            .await?;

        Ok(())
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
}

// ============================================================================
// Optional Capability: Elevated Tokens (Sudo Pattern)
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
impl<U, T, E, B> tempered_core::SupportsElevation for JwtScheme<U, T, E, B>
where
    U: UserStore + Clone + 'static,
    T: TwoFaCodeStore + Clone + 'static,
    E: EmailClient + Clone + 'static,
    B: BannedTokenStore + Clone + Send + Sync + 'static,
{
    type ElevatedToken = ElevatedJwtToken;
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
            self.elevated_jwt_config.token_ttl_in_seconds,
            self.elevated_jwt_config
                .jwt_secret
                .expose_secret()
                .as_bytes(),
        )?;

        Ok(ElevatedJwtToken(token_string))
    }
}

// ============================================================================
// HTTP Elevation Scheme - Framework-agnostic elevated token delivery
// ============================================================================

impl<U, T, E, B> tempered_core::HttpElevationScheme for JwtScheme<U, T, E, B>
where
    U: UserStore + Clone + 'static,
    T: TwoFaCodeStore + Clone + 'static,
    E: EmailClient + Clone + 'static,
    B: BannedTokenStore + Clone + Send + Sync + 'static,
{
    fn create_elevation_response<RB: AuthResponseBuilder>(
        &self,
        builder: RB,
        elevated_token: Self::ElevatedToken,
    ) -> RB::Response {
        // Use the elevated JWT config's cookie name
        let cookie = create_auth_cookie(
            elevated_token.into_string(),
            &self.elevated_jwt_config.jwt_cookie_name,
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

    fn extract_elevated_token_from_request<R: AuthRequest>(
        &self,
        req: &R,
    ) -> Option<Self::ElevatedToken> {
        // Extract from elevated cookie using elevated config's cookie name
        req.cookie(&self.elevated_jwt_config.jwt_cookie_name)
            .map(|token_str| ElevatedJwtToken(token_str.to_string()))
    }
}
