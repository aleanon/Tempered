//! Password-credential authentication scheme, generic over the token mechanism.
//!
//! This is the bulk of what was `JwtScheme`: credential login + the optional
//! capability suite (2FA, elevation, registration, password reset, email
//! verification, OAuth folding, passkey folding), written **once** and
//! parameterized over a [`TokenStrategy`] `T`. The only token-specific steps —
//! issuing, revoking, validating, and cookie delivery — are delegated to `T`, so
//! `JwtScheme` (`T = JwtTokens`) and `SessionScheme` (`T = SessionTokens`) are
//! both just type aliases over this one scheme.
//!
//! The type-state capability slots are unchanged from the JWT scheme: each
//! optional capability fills a generic slot (defaulting to `()` = disabled), and
//! its trait `impl` is gated on the real slot type, so disabled capabilities do
//! not exist at the type level.

use async_trait::async_trait;
use secrecy::{ExposeSecret, Secret};
use serde::Deserialize;
use tempered_core::{
    AuthRequest, AuthorizationRequest, CeremonyId, ChallengeStore, ClassifyError, Email,
    EmailClient, EmailVerificationStoreError, EmailVerificationToken, EmailVerificationTokenStore,
    ErrorCategory, HttpAuthenticationScheme, HttpOAuth2Scheme, HttpResponseBuilderExt,
    OAuthHttpClient, OAuthIdentityStore, OAuthStateStore, PasskeyCeremony, PasskeyCredentialStore,
    Password, PasswordResetToken, PasswordResetTokenStore, PasswordResetTokenStoreError,
    RequiresEmailVerification, ResponseBuilder, SupportsAccountDeletion, SupportsElevation,
    SupportsOAuth2, SupportsPasskeys, SupportsPasswordChange, SupportsPasswordReset,
    SupportsTokenRevocation, TwoFaAttemptId, TwoFaCode, TwoFaCodeStore, TwoFaCodeStoreError,
    TwoFaError, User, UserError, UserStore, UserStoreError, ValidatedUser, WebAuthnVerifier,
    strategies::authenticator::{
        AuthenticationScheme, LoginOutcome, SupportsRegistration, SupportsTwoFactor,
    },
};
use thiserror::Error;

use crate::authentication::token_strategy::TokenStrategy;
use crate::oauth::{OAuthFlow, OAuthFlowError};
use crate::passkey::{PasskeyFlow, PasskeyFlowError};

/// Credential scheme generic over the token mechanism `T`.
///
/// Generic slots (each defaults to `()` = disabled):
/// - `F` — two-factor      ([`TwoFa`])
/// - `L` — elevation       ([`Elevation`])
/// - `R` — password reset  ([`PasswordReset`])
/// - `M` — email verify    ([`EmailVerify`])
/// - `O` — OAuth2/OIDC      ([`OAuth`])
/// - `K` — passkeys        ([`Passkeys`])
#[derive(Clone)]
pub struct CredentialScheme<U, T, F = (), L = (), R = (), M = (), O = (), K = ()> {
    user_store: U,
    tokens: T,
    two_fa: F,
    elevation: L,
    password_reset: R,
    email_verify: M,
    oauth: O,
    passkeys: K,
    routes: RouteFlags,
}

/// Authorization level a route requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authz {
    /// A valid login session.
    Login,
    /// A valid elevated ("sudo") token.
    Elevated,
}

/// Route intents for the *always-on* capabilities (registration, password change,
/// account deletion). Their domain traits are always implemented, so whether a
/// route is exposed — and at what authz level — is plain data the delivery layer
/// reads, not type-state. Set via `supports_registration` / `supports_password_change`
/// / `supports_account_deletion` (login) and the elevation closure (elevated).
#[derive(Clone, Debug, Default)]
pub struct RouteFlags {
    pub registration: bool,
    pub password_change: Option<Authz>,
    pub account_deletion: Option<Authz>,
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

/// Enabled elevation ("sudo") slot: a *second* token strategy for short-lived
/// elevated tokens (a separate JWT config/secret, or a separate session store).
#[derive(Clone)]
pub struct Elevation<TE> {
    tokens: TE,
}

impl<TE> Elevation<TE> {
    /// Construct the elevation slot from its token strategy.
    pub fn new(tokens: TE) -> Self {
        Self { tokens }
    }
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

/// Enabled OAuth2/OIDC slot: the authorization-code flow plus the cookie/redirect
/// settings the HTTP layer needs.
#[derive(Clone)]
pub struct OAuth<ST, ID, HC> {
    flow: OAuthFlow<ST, ID, HC>,
    state_cookie_name: String,
    post_login_redirect: String,
    two_fa_redirect: String,
}

/// Enabled passkey (WebAuthn) slot: the credential ceremony flow.
#[derive(Clone)]
pub struct Passkeys<CS, ChS, V> {
    flow: PasskeyFlow<CS, ChS, V>,
}

// ============================================================================
// Internal slot traits (keep the core paths generic over the slots)
// ============================================================================

/// Removes a deleted user's passkeys during `delete_account`. `()` (passkeys
/// not configured) has nothing to remove.
#[async_trait]
trait PasskeyCleanup {
    async fn forget_user(&self, email: &Email) -> Result<(), PasskeyFlowError>;
}

#[async_trait]
impl PasskeyCleanup for () {
    async fn forget_user(&self, _email: &Email) -> Result<(), PasskeyFlowError> {
        Ok(())
    }
}

#[async_trait]
impl<CS, ChS, V> PasskeyCleanup for Passkeys<CS, ChS, V>
where
    CS: PasskeyCredentialStore + Send + Sync,
    ChS: ChallengeStore + Send + Sync,
    V: WebAuthnVerifier + Send + Sync,
{
    async fn forget_user(&self, email: &Email) -> Result<(), PasskeyFlowError> {
        self.flow.forget_user(email).await
    }
}

/// Issues the 2FA challenge during `login`. `()` rejects (2FA not configured).
#[async_trait]
trait TwoFaChallenge {
    async fn issue_challenge(&self, email: &Email) -> Result<TwoFaAttemptId, TwoFaChallengeError>;
}

#[async_trait]
impl TwoFaChallenge for () {
    async fn issue_challenge(&self, _email: &Email) -> Result<TwoFaAttemptId, TwoFaChallengeError> {
        Err(TwoFaChallengeError::NotConfigured)
    }
}

#[async_trait]
impl<S, E> TwoFaChallenge for TwoFa<S, E>
where
    S: TwoFaCodeStore + Send + Sync,
    E: EmailClient + Send + Sync,
{
    async fn issue_challenge(&self, email: &Email) -> Result<TwoFaAttemptId, TwoFaChallengeError> {
        let attempt_id = TwoFaAttemptId::new();
        let code = TwoFaCode::new();

        self.store
            .store_code(email.clone(), attempt_id.clone(), code.clone())
            .await?;

        self.email
            .send_email(email, "2FA Code", code.as_str())
            .await
            .map_err(TwoFaChallengeError::Email)?;

        Ok(attempt_id)
    }
}

/// Token-agnostic error from the 2FA challenge step; converted into the scheme's
/// `CredentialError` (independent of the token strategy).
#[derive(Debug, Error)]
enum TwoFaChallengeError {
    #[error("Two-factor authentication is required but not configured for this scheme")]
    NotConfigured,
    #[error("2FA code store error: {0}")]
    Store(#[from] TwoFaCodeStoreError),
    #[error("Failed to send email: {0}")]
    Email(String),
}

impl<TE> From<TwoFaChallengeError> for CredentialError<TE>
where
    TE: std::error::Error + Send + Sync + 'static,
{
    fn from(e: TwoFaChallengeError) -> Self {
        match e {
            TwoFaChallengeError::NotConfigured => CredentialError::TwoFaNotConfigured,
            TwoFaChallengeError::Store(s) => CredentialError::TwoFaCodeStoreError(s),
            TwoFaChallengeError::Email(m) => CredentialError::EmailError(m),
        }
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

impl<TE: TokenStrategy> ElevatedCookieName for Elevation<TE> {
    fn elevated_cookie_name(&self) -> Option<&str> {
        Some(self.tokens.cookie_name())
    }
}

// ============================================================================
// Builders (token-agnostic): from_tokens() + supports_*()
// ============================================================================

impl<U, T, F, L, R, M, O, K> CredentialScheme<U, T, F, L, R, M, O, K> {
    /// The scheme's token strategy (used by per-strategy builders, e.g. to
    /// share infrastructure with a companion elevated-token strategy).
    pub(crate) fn token_strategy(&self) -> &T {
        &self.tokens
    }
}

impl<U, T> CredentialScheme<U, T, (), (), (), (), (), ()>
where
    U: UserStore,
    T: TokenStrategy,
{
    /// Create the core scheme from a user store and a token strategy.
    ///
    /// Per-strategy constructors (e.g. `JwtScheme::new`) wrap this.
    pub fn from_tokens(user_store: U, tokens: T) -> Self {
        Self {
            user_store,
            tokens,
            two_fa: (),
            elevation: (),
            password_reset: (),
            email_verify: (),
            oauth: (),
            passkeys: (),
            routes: RouteFlags::default(),
        }
    }
}

impl<U, T, L, R, M, O, K> CredentialScheme<U, T, (), L, R, M, O, K> {
    /// Enable two-factor authentication, lighting up [`SupportsTwoFactor`].
    pub fn supports_2fa<S, E>(
        self,
        store: S,
        email: E,
    ) -> CredentialScheme<U, T, TwoFa<S, E>, L, R, M, O, K> {
        CredentialScheme {
            user_store: self.user_store,
            tokens: self.tokens,
            two_fa: TwoFa { store, email },
            elevation: self.elevation,
            password_reset: self.password_reset,
            email_verify: self.email_verify,
            oauth: self.oauth,
            passkeys: self.passkeys,
            routes: self.routes,
        }
    }
}

impl<U, T, F, R, M, O, K> CredentialScheme<U, T, F, (), R, M, O, K> {
    /// Enable elevated ("sudo") tokens from a second token strategy, lighting up
    /// [`SupportsElevation`] and [`tempered_core::HttpElevationScheme`].
    ///
    /// Per-strategy sugar (e.g. `JwtScheme::supports_elevation(banned, config, |e| …)`)
    /// wraps this with the matching strategy. `configure` declares which sensitive
    /// operations require an elevated token (served under `/elevated/…`).
    pub fn supports_elevation_with<TE, Cfg>(
        mut self,
        elevated_tokens: TE,
        configure: Cfg,
    ) -> CredentialScheme<U, T, F, Elevation<TE>, R, M, O, K>
    where
        Cfg: FnOnce(ElevatedCapabilities) -> ElevatedCapabilities,
    {
        let caps = configure(ElevatedCapabilities::default());
        if caps.password_change {
            self.routes.password_change = Some(Authz::Elevated);
        }
        if caps.account_deletion {
            self.routes.account_deletion = Some(Authz::Elevated);
        }

        CredentialScheme {
            user_store: self.user_store,
            tokens: self.tokens,
            two_fa: self.two_fa,
            elevation: Elevation {
                tokens: elevated_tokens,
            },
            password_reset: self.password_reset,
            email_verify: self.email_verify,
            oauth: self.oauth,
            passkeys: self.passkeys,
            routes: self.routes,
        }
    }
}

impl<U, T, F, L, M, O, K> CredentialScheme<U, T, F, L, (), M, O, K> {
    /// Enable password reset, lighting up [`SupportsPasswordReset`].
    pub fn supports_password_reset<P, E>(
        self,
        store: P,
        email: E,
    ) -> CredentialScheme<U, T, F, L, PasswordReset<P, E>, M, O, K> {
        CredentialScheme {
            user_store: self.user_store,
            tokens: self.tokens,
            two_fa: self.two_fa,
            elevation: self.elevation,
            password_reset: PasswordReset { store, email },
            email_verify: self.email_verify,
            oauth: self.oauth,
            passkeys: self.passkeys,
            routes: self.routes,
        }
    }
}

impl<U, T, F, L, R, O, K> CredentialScheme<U, T, F, L, R, (), O, K> {
    /// Enable email verification, lighting up [`RequiresEmailVerification`].
    pub fn supports_email_verification<V, E>(
        self,
        store: V,
        email: E,
    ) -> CredentialScheme<U, T, F, L, R, EmailVerify<V, E>, O, K> {
        CredentialScheme {
            user_store: self.user_store,
            tokens: self.tokens,
            two_fa: self.two_fa,
            elevation: self.elevation,
            password_reset: self.password_reset,
            email_verify: EmailVerify { store, email },
            oauth: self.oauth,
            passkeys: self.passkeys,
            routes: self.routes,
        }
    }
}

impl<U, T, F, L, R, M, K> CredentialScheme<U, T, F, L, R, M, (), K> {
    /// Enable OAuth2/OIDC login, lighting up [`SupportsOAuth2`] and
    /// [`tempered_core::HttpOAuth2Scheme`].
    // The return type spells out every capability slot on purpose: it is the
    // typestate transition. An alias would hide which slot changes.
    #[allow(clippy::type_complexity)]
    pub fn supports_oauth<ST, ID, HC>(
        self,
        flow: OAuthFlow<ST, ID, HC>,
    ) -> CredentialScheme<U, T, F, L, R, M, OAuth<ST, ID, HC>, K> {
        CredentialScheme {
            user_store: self.user_store,
            tokens: self.tokens,
            two_fa: self.two_fa,
            elevation: self.elevation,
            password_reset: self.password_reset,
            email_verify: self.email_verify,
            oauth: OAuth {
                flow,
                state_cookie_name: "oauth_state".to_string(),
                post_login_redirect: "/".to_string(),
                two_fa_redirect: "/".to_string(),
            },
            passkeys: self.passkeys,
            routes: self.routes,
        }
    }
}

impl<U, T, F, L, R, M, O> CredentialScheme<U, T, F, L, R, M, O, ()> {
    /// Enable passkey (WebAuthn) authentication, lighting up [`SupportsPasskeys`].
    // The return type spells out every capability slot on purpose: it is the
    // typestate transition. An alias would hide which slot changes.
    #[allow(clippy::type_complexity)]
    pub fn supports_passkeys<CS, ChS, V>(
        self,
        flow: PasskeyFlow<CS, ChS, V>,
    ) -> CredentialScheme<U, T, F, L, R, M, O, Passkeys<CS, ChS, V>> {
        CredentialScheme {
            user_store: self.user_store,
            tokens: self.tokens,
            two_fa: self.two_fa,
            elevation: self.elevation,
            password_reset: self.password_reset,
            email_verify: self.email_verify,
            oauth: self.oauth,
            passkeys: Passkeys { flow },
            routes: self.routes,
        }
    }
}

impl<U, T, F, L, R, M, ST, ID, HC, K> CredentialScheme<U, T, F, L, R, M, OAuth<ST, ID, HC>, K> {
    /// Override the cookie name used to bind the OAuth `state` to the browser
    /// (default `oauth_state`).
    pub fn oauth_state_cookie(mut self, name: impl Into<String>) -> Self {
        self.oauth.state_cookie_name = name.into();
        self
    }

    /// Override where the browser is redirected after a successful OAuth callback
    /// (default `/`).
    pub fn oauth_post_login_redirect(mut self, path: impl Into<String>) -> Self {
        self.oauth.post_login_redirect = path.into();
        self
    }

    /// Override where the browser is redirected when an OAuth login reaches an
    /// account that requires two-factor authentication (default `/`).
    ///
    /// No session is issued on that redirect. It carries three query
    /// parameters — `oauth_2fa=required`, `loginAttemptId` and `email` — which
    /// are exactly what the page needs to prompt for the code and call the
    /// 2FA verification route, as after a password login that returns
    /// `requires_2fa`.
    pub fn oauth_two_fa_redirect(mut self, path: impl Into<String>) -> Self {
        self.oauth.two_fa_redirect = path.into();
        self
    }
}

impl<U, T, F, L, R, M, O, K> CredentialScheme<U, T, F, L, R, M, O, K> {
    /// Finalizer for readability; the scheme is already usable. Returns `self`.
    pub fn build(self) -> Self {
        self
    }

    pub fn user_store(&self) -> &U {
        &self.user_store
    }

    /// The route intents (which always-on capabilities are exposed, at what level).
    /// Read by the delivery layer to auto-wire routes.
    pub fn route_flags(&self) -> &RouteFlags {
        &self.routes
    }

    /// Expose the self-service **signup** route (`/signup`).
    pub fn supports_registration(mut self) -> Self {
        self.routes.registration = true;
        self
    }

    /// Expose **password change** at the login level (`/change-password`). To
    /// require elevation instead, declare it inside the `supports_elevation` closure.
    pub fn supports_password_change(mut self) -> Self {
        self.routes.password_change = Some(Authz::Login);
        self
    }

    /// Expose **account deletion** at the login level (`/delete-account`). To
    /// require elevation instead, declare it inside the `supports_elevation` closure.
    pub fn supports_account_deletion(mut self) -> Self {
        self.routes.account_deletion = Some(Authz::Login);
        self
    }
}

/// Sub-builder passed to [`CredentialScheme::supports_elevation_with`]'s closure:
/// declares which sensitive operations require an elevated token (they are then
/// served under `/elevated/…`).
#[derive(Debug, Default)]
pub struct ElevatedCapabilities {
    password_change: bool,
    account_deletion: bool,
}

impl ElevatedCapabilities {
    /// Require elevation for password change (`/elevated/change-password`).
    pub fn supports_password_change(mut self) -> Self {
        self.password_change = true;
        self
    }

    /// Require elevation for account deletion (`/elevated/delete-account`).
    pub fn supports_account_deletion(mut self) -> Self {
        self.account_deletion = true;
        self
    }
}

impl<U, T, F, L, R, M, O, K> CredentialScheme<U, T, F, L, R, M, O, K>
where
    T: TokenStrategy,
{
    pub fn cookie_name(&self) -> &str {
        self.tokens.cookie_name()
    }
}

// ============================================================================
// HTTP Authentication Scheme - framework-agnostic token delivery
// ============================================================================

#[async_trait]
impl<U, T, F, L, R, M, O, K> HttpAuthenticationScheme for CredentialScheme<U, T, F, L, R, M, O, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: ElevatedCookieName + Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    K: Clone + Send + Sync + 'static,
{
    fn create_login_response<RB: ResponseBuilder>(
        &self,
        builder: RB,
        outcome: LoginOutcome<Self::Token>,
    ) -> Result<RB::Response, tempered_core::ResponseBuilderError> {
        match outcome {
            LoginOutcome::Success(token) => builder
                .status(200)
                .cookie(&self.tokens.auth_cookie(&token))
                .json_body(serde_json::json!({
                    "status": "success",
                    "message": "Login successful"
                }))
                .build(),
            LoginOutcome::Requires2Fa {
                email: _,
                attempt_id,
            } => builder
                .status(206)
                .json_body(serde_json::json!({
                    "status": "requires_2fa",
                    "message": "2FA required",
                    "loginAttemptId": attempt_id.to_string()
                }))
                .build(),
        }
    }

    fn create_logout_response<RB: ResponseBuilder>(
        &self,
        builder: RB,
        cookie_name: Option<String>,
    ) -> Result<RB::Response, tempered_core::ResponseBuilderError> {
        let cookie_name = cookie_name.unwrap_or_else(|| self.tokens.cookie_name().to_string());

        let clear_cookie = format!(
            "{}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
            cookie_name
        );
        let builder = builder.status(200).cookie(&clear_cookie);

        // Also clear the elevated cookie, but only if elevation is enabled.
        let builder = match self.elevation.elevated_cookie_name() {
            Some(name) => builder.cookie(&format!(
                "{}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
                name
            )),
            None => builder,
        };

        builder
            .json_body(serde_json::json!({ "message": "Logged out successfully" }))
            .build()
    }

    fn extract_token_from_request<Req: AuthRequest>(&self, req: &Req) -> Option<Self::Token> {
        self.tokens.extract(req)
    }
}

// ============================================================================
// Core Trait: AuthenticationScheme
// ============================================================================

#[async_trait]
impl<U, T, F, L, R, M, O, K> AuthenticationScheme for CredentialScheme<U, T, F, L, R, M, O, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    K: Clone + Send + Sync + 'static,
{
    type Token = T::Token;
    type Validator = T::Validator;
    type LogoutOutput = String;
    type Credentials = PasswordCredentials;
    type AuthError = CredentialError<T::Error>;

    #[tracing::instrument(name = "CredentialScheme::login", skip(self, credentials))]
    async fn login(
        &self,
        credentials: Self::Credentials,
    ) -> Result<LoginOutcome<Self::Token>, Self::AuthError> {
        let email = Email::try_from(credentials.email)?;
        let password = Password::try_from(credentials.password)?;

        let validated_user = self.user_store.authenticate_user(&email, &password).await?;

        match validated_user {
            ValidatedUser::Requires2Fa(email) => {
                // Delegate to the 2FA slot: issues + delivers the challenge, or
                // errors if the scheme was built without `supports_2fa`.
                let attempt_id = self.two_fa.issue_challenge(&email).await?;
                Ok(LoginOutcome::Requires2Fa { email, attempt_id })
            }
            ValidatedUser::No2Fa(email) => {
                let token = self
                    .tokens
                    .issue(&email)
                    .await
                    .map_err(CredentialError::Token)?;
                Ok(LoginOutcome::Success(token))
            }
        }
    }

    async fn logout(&self, token: &Self::Token) -> Result<Self::LogoutOutput, Self::AuthError> {
        self.tokens
            .revoke(token)
            .await
            .map_err(CredentialError::Token)?;
        Ok(self.tokens.cookie_name().to_string())
    }

    fn validator(&self) -> &Self::Validator {
        self.tokens.validator()
    }
}

// ============================================================================
// Always-on capabilities (need only the user store)
// ============================================================================

#[async_trait]
impl<U, T, F, L, R, M, O, K> SupportsRegistration for CredentialScheme<U, T, F, L, R, M, O, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    K: Clone + Send + Sync + 'static,
{
    type RegistrationData = RegistrationData;
    type RegistrationError = CredentialError<T::Error>;

    #[tracing::instrument(name = "CredentialScheme::register", skip(self, password))]
    async fn register(
        &self,
        email: Email,
        password: Password,
        data: Self::RegistrationData,
    ) -> Result<(), Self::RegistrationError> {
        let user = User::new(email, password, data.requires_2fa);
        self.user_store.add_user(user).await?;
        Ok(())
    }
}

#[async_trait]
impl<U, T, F, L, R, M, O, K> SupportsPasswordChange for CredentialScheme<U, T, F, L, R, M, O, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    K: Clone + Send + Sync + 'static,
{
    type PasswordChangeError = CredentialError<T::Error>;

    #[tracing::instrument(name = "CredentialScheme::change_password", skip(self, new_password))]
    async fn change_password(
        &self,
        email: Email,
        new_password: Password,
    ) -> Result<(), Self::PasswordChangeError> {
        self.user_store
            .set_new_password(&email, new_password)
            .await?;
        // A password change must strand whoever was holding the old password's
        // sessions — revoke every outstanding token (all devices).
        self.tokens
            .revoke_all_for_user(&email)
            .await
            .map_err(CredentialError::Token)?;
        Ok(())
    }
}

#[async_trait]
impl<U, T, F, L, R, M, O, K> SupportsAccountDeletion for CredentialScheme<U, T, F, L, R, M, O, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    K: PasskeyCleanup + Clone + Send + Sync + 'static,
{
    type AccountDeletionError = CredentialError<T::Error>;

    #[tracing::instrument(name = "CredentialScheme::delete_account", skip(self))]
    async fn delete_account(&self, email: Email) -> Result<(), Self::AccountDeletionError> {
        // Order matters: everything that can log in as this user goes first,
        // the account last. If a step fails, what remains is an account with
        // fewer credentials — never credentials or sessions without an account.

        // Passkeys are a login credential for this account: remove them, so
        // they cannot outlive it or be inherited by a later account that
        // reuses the address.
        self.passkeys.forget_user(&email).await?;
        // A deleted user's token would otherwise keep validating until it
        // expires (JWT validation is signature-based, not a user-store read).
        self.tokens
            .revoke_all_for_user(&email)
            .await
            .map_err(CredentialError::Token)?;
        self.user_store.delete_user(&email).await?;
        Ok(())
    }
}

// Token revocation is just the strategy's `revoke` (used by stateful sessions to
// delete server-side; by JWT to ban). Always available.
#[async_trait]
impl<U, T, F, L, R, M, O, K> SupportsTokenRevocation for CredentialScheme<U, T, F, L, R, M, O, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    K: Clone + Send + Sync + 'static,
{
    type RevocationError = CredentialError<T::Error>;

    async fn revoke_token(&self, token: &Self::Token) -> Result<(), Self::RevocationError> {
        self.tokens
            .revoke(token)
            .await
            .map_err(CredentialError::Token)?;
        Ok(())
    }
}

// ============================================================================
// Two-Factor Authentication (gated on the `TwoFa` slot)
// ============================================================================

#[async_trait]
impl<U, T, S, E, L, R, M, O, K> SupportsTwoFactor
    for CredentialScheme<U, T, TwoFa<S, E>, L, R, M, O, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    S: TwoFaCodeStore + Clone + Send + Sync + 'static,
    E: EmailClient + Clone + Send + Sync + 'static,
    L: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    K: Clone + Send + Sync + 'static,
{
    type TwoFactorError = CredentialError<T::Error>;

    #[tracing::instrument(name = "CredentialScheme::verify_2fa", skip(self, code))]
    async fn verify_2fa(
        &self,
        email: Email,
        attempt_id: TwoFaAttemptId,
        code: TwoFaCode,
    ) -> Result<Self::Token, Self::TwoFactorError> {
        self.two_fa
            .store
            .validate(&email, &attempt_id, &code)
            .await?;
        self.two_fa.store.delete(&email).await?;
        Ok(self
            .tokens
            .issue(&email)
            .await
            .map_err(CredentialError::Token)?)
    }
}

// ============================================================================
// Elevated Tokens / "Sudo" (gated on the `Elevation` slot)
// ============================================================================

#[async_trait]
impl<U, T, F, TE, R, M, O, K> SupportsElevation
    for CredentialScheme<U, T, F, Elevation<TE>, R, M, O, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    TE: TokenStrategy,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    K: Clone + Send + Sync + 'static,
{
    type ElevatedToken = TE::Token;
    type ElevatedValidator = TE::Validator;
    type ElevationError = CredentialError<TE::Error>;

    #[tracing::instrument(name = "CredentialScheme::elevate", skip(self, password))]
    async fn elevate(
        &self,
        email: Email,
        password: Password,
    ) -> Result<Self::ElevatedToken, Self::ElevationError> {
        // Re-authenticate, then mint a token via the *elevated* strategy.
        self.user_store.authenticate_user(&email, &password).await?;
        Ok(self
            .elevation
            .tokens
            .issue(&email)
            .await
            .map_err(CredentialError::Token)?)
    }

    fn elevated_validator(&self) -> &Self::ElevatedValidator {
        self.elevation.tokens.validator()
    }

    async fn revoke_elevated_token(
        &self,
        token: &Self::ElevatedToken,
    ) -> Result<(), Self::ElevationError> {
        self.elevation
            .tokens
            .revoke(token)
            .await
            .map_err(CredentialError::Token)?;
        Ok(())
    }
}

impl<U, T, F, TE, R, M, O, K> tempered_core::HttpElevationScheme
    for CredentialScheme<U, T, F, Elevation<TE>, R, M, O, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    TE: TokenStrategy,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    K: Clone + Send + Sync + 'static,
{
    fn create_elevation_response<RB: ResponseBuilder>(
        &self,
        builder: RB,
        elevated_token: Self::ElevatedToken,
    ) -> Result<RB::Response, tempered_core::ResponseBuilderError> {
        builder
            .status(200)
            .cookie(&self.elevation.tokens.auth_cookie(&elevated_token))
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
        self.elevation.tokens.extract(req)
    }
}

// ============================================================================
// Password Reset (gated on the `PasswordReset` slot)
// ============================================================================

#[async_trait]
impl<U, T, F, L, P, E, M, O, K> SupportsPasswordReset
    for CredentialScheme<U, T, F, L, PasswordReset<P, E>, M, O, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: Clone + Send + Sync + 'static,
    P: PasswordResetTokenStore + Clone + Send + Sync + 'static,
    E: EmailClient + Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    K: Clone + Send + Sync + 'static,
{
    type PasswordResetError = CredentialError<T::Error>;

    #[tracing::instrument(name = "CredentialScheme::initiate_password_reset", skip(self))]
    async fn initiate_password_reset(&self, email: Email) -> Result<(), Self::PasswordResetError> {
        // Silent Ok if the user doesn't exist (prevents email enumeration).
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
            .map_err(CredentialError::EmailError)?;
        Ok(())
    }

    #[tracing::instrument(
        name = "CredentialScheme::complete_password_reset",
        skip(self, new_password, reset_token)
    )]
    async fn complete_password_reset(
        &self,
        reset_token: String,
        new_password: Password,
    ) -> Result<(), Self::PasswordResetError> {
        let token =
            PasswordResetToken::parse(&reset_token).ok_or(CredentialError::InvalidResetToken)?;

        // Atomically redeem the token before touching the password: two
        // concurrent requests can't both pass a check-then-delete, and if the
        // password update fails the token is burned (the user re-initiates)
        // rather than left valid after a successful change.
        let email = self
            .password_reset
            .store
            .consume_token(&token)
            .await
            .map_err(|_| CredentialError::InvalidResetToken)?;

        self.user_store
            .set_new_password(&email, new_password)
            .await?;

        // A reset is a password change — typically *because* the account may
        // be compromised — so strand every outstanding session.
        self.tokens
            .revoke_all_for_user(&email)
            .await
            .map_err(CredentialError::Token)?;

        Ok(())
    }
}

// ============================================================================
// Email Verification (gated on the `EmailVerify` slot)
// ============================================================================

#[async_trait]
impl<U, T, F, L, R, V, E, O, K> RequiresEmailVerification
    for CredentialScheme<U, T, F, L, R, EmailVerify<V, E>, O, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    V: EmailVerificationTokenStore + Clone + Send + Sync + 'static,
    E: EmailClient + Clone + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    K: Clone + Send + Sync + 'static,
{
    type EmailVerificationError = CredentialError<T::Error>;

    #[tracing::instrument(name = "CredentialScheme::initiate_email_verification", skip(self))]
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
            .map_err(CredentialError::EmailError)?;
        Ok(())
    }

    #[tracing::instrument(name = "CredentialScheme::verify_email", skip(self, token))]
    async fn verify_email(&self, token: String) -> Result<(), Self::EmailVerificationError> {
        let token = EmailVerificationToken::parse(&token)
            .ok_or(CredentialError::InvalidVerificationToken)?;

        let email = self
            .email_verify
            .store
            .consume_token(&token)
            .await
            .map_err(|_| CredentialError::InvalidVerificationToken)?;

        self.email_verify.store.mark_verified(&email).await?;
        Ok(())
    }

    #[tracing::instrument(name = "CredentialScheme::is_email_verified", skip(self))]
    async fn is_email_verified(&self, email: &Email) -> Result<bool, Self::EmailVerificationError> {
        Ok(self.email_verify.store.is_verified(email).await?)
    }
}

// ============================================================================
// OAuth2 / OIDC (gated on the `OAuth` slot)
// ============================================================================

#[async_trait]
impl<U, T, F, L, R, M, ST, ID, HC, K> SupportsOAuth2
    for CredentialScheme<U, T, F, L, R, M, OAuth<ST, ID, HC>, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
    ST: OAuthStateStore + Clone + Send + Sync + 'static,
    ID: OAuthIdentityStore + Clone + Send + Sync + 'static,
    HC: OAuthHttpClient + Clone + Send + Sync + 'static,
    K: Clone + Send + Sync + 'static,
{
    type OAuth2Error = CredentialError<T::Error>;

    #[tracing::instrument(name = "CredentialScheme::begin_oauth", skip(self))]
    async fn begin_oauth(&self, provider: &str) -> Result<AuthorizationRequest, Self::OAuth2Error> {
        Ok(self.oauth.flow.begin(provider).await?)
    }

    #[tracing::instrument(name = "CredentialScheme::complete_oauth", skip(self, code))]
    async fn complete_oauth(
        &self,
        provider: &str,
        code: &str,
        query_state: &str,
        cookie_state: &str,
    ) -> Result<LoginOutcome<Self::Token>, Self::OAuth2Error> {
        // The flow verifies the provider identity and yields a verified email.
        let email = self
            .oauth
            .flow
            .complete(provider, code, query_state, cookie_state)
            .await?;

        // From here it is an ordinary login to that email's account, creating
        // the account first if this is the user's first visit.
        let requires_2fa = match self.user_store.get_user(&email).await {
            Ok(user) => user.requires_2fa,
            Err(UserStoreError::UserNotFound) => {
                self.create_account_for_provider_login(&email).await?
            }
            Err(e) => return Err(e.into()),
        };

        if requires_2fa {
            // The provider stands in for the password, not for the second
            // factor. Same path as password login: issue + deliver the
            // challenge, or error if the scheme was built without 2FA.
            let attempt_id = self.two_fa.issue_challenge(&email).await?;
            return Ok(LoginOutcome::Requires2Fa { email, attempt_id });
        }

        let token = self
            .tokens
            .issue(&email)
            .await
            .map_err(CredentialError::Token)?;
        Ok(LoginOutcome::Success(token))
    }
}

impl<U, T, F, L, R, M, O, K> CredentialScheme<U, T, F, L, R, M, O, K>
where
    U: UserStore,
{
    /// Create the local account for a first-time provider login, returning
    /// whether the account that now exists requires 2FA.
    ///
    /// The provider has verified the address, so no email verification is
    /// needed. The user store requires a password, so the account gets a random
    /// one that nobody knows: the user keeps signing in through the provider,
    /// and can set a real password through password reset if the scheme
    /// offers it.
    async fn create_account_for_provider_login(
        &self,
        email: &Email,
    ) -> Result<bool, UserStoreError> {
        let user = User::new(email.clone(), unknowable_password(), false);
        match self.user_store.add_user(user).await {
            Ok(()) => Ok(false),
            // Lost a race with another request creating the same account (a
            // signup, or a second callback): log in to the one that exists.
            Err(UserStoreError::UserAlreadyExists) => {
                Ok(self.user_store.get_user(email).await?.requires_2fa)
            }
            Err(e) => Err(e),
        }
    }
}

/// A password no one can know or guess: 32 random bytes, base64url-encoded.
fn unknowable_password() -> Password {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand::RngCore;

    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    Password::try_from(Secret::new(URL_SAFE_NO_PAD.encode(buf)))
        .expect("a 43-character password satisfies the length rule")
}

impl<U, T, F, L, R, M, ST, ID, HC, K> HttpOAuth2Scheme
    for CredentialScheme<U, T, F, L, R, M, OAuth<ST, ID, HC>, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: ElevatedCookieName + Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
    ST: OAuthStateStore + Clone + Send + Sync + 'static,
    ID: OAuthIdentityStore + Clone + Send + Sync + 'static,
    HC: OAuthHttpClient + Clone + Send + Sync + 'static,
    K: Clone + Send + Sync + 'static,
{
    fn oauth_state_cookie_name(&self) -> &str {
        &self.oauth.state_cookie_name
    }

    fn create_oauth_start_response<RB: ResponseBuilder>(
        &self,
        builder: RB,
        authorization: AuthorizationRequest,
    ) -> Result<RB::Response, tempered_core::ResponseBuilderError> {
        // Max-Age bounds how long the CSRF state cookie lingers if the user
        // abandons the flow; 10 minutes is ample to complete a provider redirect.
        let state_cookie = format!(
            "{}={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600",
            self.oauth.state_cookie_name, authorization.state
        );

        builder
            .status(302)
            .cookie(&state_cookie)
            .header("location", &authorization.authorize_url)
            .build()
    }

    fn create_oauth_callback_response<RB: ResponseBuilder>(
        &self,
        builder: RB,
        outcome: LoginOutcome<Self::Token>,
    ) -> Result<RB::Response, tempered_core::ResponseBuilderError> {
        // Either way the state cookie is spent.
        let clear_state = format!(
            "{}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
            self.oauth.state_cookie_name
        );
        let builder = builder.status(302).cookie(&clear_state);

        match outcome {
            // Deliver the issued token exactly as login does and enter the app.
            LoginOutcome::Success(token) => builder
                .cookie(&self.tokens.auth_cookie(&token))
                .header("location", &self.oauth.post_login_redirect)
                .build(),
            // No token yet: send the browser to the app's second-factor step
            // with what it needs to call the 2FA verification route.
            LoginOutcome::Requires2Fa { email, attempt_id } => builder
                .header(
                    "location",
                    &two_fa_redirect_location(&self.oauth.two_fa_redirect, &email, &attempt_id),
                )
                .build(),
        }
    }
}

/// `base` plus the query parameters a page needs to finish a 2FA login:
/// `oauth_2fa=required`, `loginAttemptId`, `email`. Keeps any query string or
/// fragment `base` already has.
fn two_fa_redirect_location(base: &str, email: &Email, attempt_id: &TwoFaAttemptId) -> String {
    let (path_and_query, fragment) = match base.split_once('#') {
        Some((before, after)) => (before, Some(after)),
        None => (base, None),
    };
    let params = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("oauth_2fa", "required")
        .append_pair("loginAttemptId", &attempt_id.to_string())
        .append_pair("email", email.as_ref().expose_secret())
        .finish();
    let separator = if path_and_query.contains('?') {
        '&'
    } else {
        '?'
    };
    let mut location = format!("{path_and_query}{separator}{params}");
    if let Some(fragment) = fragment {
        location.push('#');
        location.push_str(fragment);
    }
    location
}

// ============================================================================
// Passkeys / WebAuthn (gated on the `Passkeys` slot)
// ============================================================================

#[async_trait]
impl<U, T, F, L, R, M, O, CS, ChS, V> SupportsPasskeys
    for CredentialScheme<U, T, F, L, R, M, O, Passkeys<CS, ChS, V>>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    CS: PasskeyCredentialStore + Clone + Send + Sync + 'static,
    ChS: ChallengeStore + Clone + Send + Sync + 'static,
    V: WebAuthnVerifier + Clone + Send + Sync + 'static,
{
    type PasskeyError = CredentialError<T::Error>;

    #[tracing::instrument(name = "CredentialScheme::start_passkey_registration", skip(self))]
    async fn start_passkey_registration(
        &self,
        email: Email,
    ) -> Result<PasskeyCeremony, Self::PasskeyError> {
        Ok(self.passkeys.flow.start_registration(email).await?)
    }

    #[tracing::instrument(
        name = "CredentialScheme::finish_passkey_registration",
        skip(self, response)
    )]
    async fn finish_passkey_registration(
        &self,
        email: Email,
        ceremony_id: CeremonyId,
        response: serde_json::Value,
    ) -> Result<(), Self::PasskeyError> {
        self.passkeys
            .flow
            .finish_registration(&email, ceremony_id, response)
            .await?;
        Ok(())
    }

    #[tracing::instrument(name = "CredentialScheme::start_passkey_authentication", skip(self))]
    async fn start_passkey_authentication(
        &self,
        email: Option<Email>,
    ) -> Result<PasskeyCeremony, Self::PasskeyError> {
        Ok(self.passkeys.flow.start_authentication(email).await?)
    }

    #[tracing::instrument(
        name = "CredentialScheme::finish_passkey_authentication",
        skip(self, response)
    )]
    async fn finish_passkey_authentication(
        &self,
        ceremony_id: CeremonyId,
        response: serde_json::Value,
    ) -> Result<Self::Token, Self::PasskeyError> {
        let email = self
            .passkeys
            .flow
            .finish_authentication(ceremony_id, response)
            .await?;
        // A passkey outlives nothing: if the account it was enrolled for is gone
        // (deleted since enrollment), the credential must not mint a session.
        self.user_store.get_user(&email).await?;
        Ok(self
            .tokens
            .issue(&email)
            .await
            .map_err(CredentialError::Token)?)
    }
}

// ============================================================================
// Wire types
// ============================================================================

/// Credentials for password-based login.
#[derive(Debug, Deserialize)]
pub struct PasswordCredentials {
    pub email: Secret<String>,
    pub password: Secret<String>,
}

/// Additional data needed for user registration.
#[derive(Debug, Deserialize)]
pub struct RegistrationData {
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

// ============================================================================
// Error type (generic over the token strategy's error)
// ============================================================================

#[derive(Debug, Error)]
pub enum CredentialError<TE: std::error::Error + Send + Sync + 'static> {
    #[error("User error: {0}")]
    UserError(#[from] UserError),

    #[error("User store error: {0}")]
    UserStoreError(#[from] UserStoreError),

    #[error("Token error: {0}")]
    Token(TE),

    #[error("Two-factor authentication error: {0}")]
    TwoFaError(#[from] TwoFaError),

    #[error("Two-factor authentication is required but not configured for this scheme")]
    TwoFaNotConfigured,

    #[error("2FA code store error: {0}")]
    TwoFaCodeStoreError(#[from] TwoFaCodeStoreError),

    #[error("Failed to send email: {0}")]
    EmailError(String),

    #[error("Invalid or expired password reset token")]
    InvalidResetToken,

    #[error("Password reset token store error: {0}")]
    PasswordResetTokenStoreError(#[from] PasswordResetTokenStoreError),

    #[error("Invalid or expired email verification token")]
    InvalidVerificationToken,

    #[error("Email verification store error: {0}")]
    EmailVerificationStoreError(#[from] EmailVerificationStoreError),

    #[error("OAuth error: {0}")]
    OAuth(#[from] OAuthFlowError),

    #[error("Passkey error: {0}")]
    Passkey(#[from] PasskeyFlowError),
}

impl<TE> ClassifyError for CredentialError<TE>
where
    TE: std::error::Error + Send + Sync + 'static + ClassifyError,
{
    fn classify(self) -> (ErrorCategory, String) {
        match self {
            CredentialError::UserError(e) => (ErrorCategory::BadRequest, e.to_string()),

            // Same status and body for "no such user" and "wrong password" so
            // login cannot be used to enumerate registered accounts.
            CredentialError::UserStoreError(
                UserStoreError::UserNotFound | UserStoreError::IncorrectPassword,
            ) => (
                ErrorCategory::Unauthorized,
                "Invalid email or password".to_string(),
            ),
            CredentialError::UserStoreError(UserStoreError::UserAlreadyExists) => {
                (ErrorCategory::Conflict, "User already exists".to_string())
            }

            CredentialError::TwoFaError(e) => (ErrorCategory::Unauthorized, e.to_string()),
            // Distinct, safe-to-reveal signal: the code is burned and the user
            // must log in again for a fresh one.
            CredentialError::TwoFaCodeStoreError(TwoFaCodeStoreError::TooManyAttempts) => (
                ErrorCategory::TooManyRequests,
                "Too many failed attempts; log in again for a new code".to_string(),
            ),
            CredentialError::TwoFaCodeStoreError(e) => {
                tracing::error!(error = %e, "2FA code store error");
                (
                    ErrorCategory::Unauthorized,
                    "Invalid or expired 2FA code".to_string(),
                )
            }
            CredentialError::TwoFaNotConfigured => (
                ErrorCategory::Internal,
                "Two-factor authentication is required but not configured".to_string(),
            ),

            // Token errors use their own mapping (JWT signing / ban-store, …).
            CredentialError::Token(e) => e.classify(),

            CredentialError::InvalidResetToken => (
                ErrorCategory::BadRequest,
                "Invalid or expired password reset token".to_string(),
            ),

            CredentialError::UserStoreError(e) => {
                tracing::error!(error = %e, "user store error");
                (ErrorCategory::Internal, "Internal error".to_string())
            }
            CredentialError::EmailError(e) => {
                tracing::error!(error = %e, "email send error");
                (ErrorCategory::Internal, "Internal error".to_string())
            }
            CredentialError::PasswordResetTokenStoreError(e) => {
                tracing::error!(error = %e, "password reset token store error");
                (ErrorCategory::Internal, "Internal error".to_string())
            }

            CredentialError::InvalidVerificationToken => (
                ErrorCategory::BadRequest,
                "Invalid or expired email verification token".to_string(),
            ),
            CredentialError::EmailVerificationStoreError(e) => {
                tracing::error!(error = %e, "email verification store error");
                (ErrorCategory::Internal, "Internal error".to_string())
            }

            CredentialError::OAuth(e) => e.classify(),
            CredentialError::Passkey(e) => e.classify(),
        }
    }
}
