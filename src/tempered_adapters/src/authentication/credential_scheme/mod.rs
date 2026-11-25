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

use std::sync::Arc;

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
    SupportsTokenRevocation, SupportsTotp, TotpEnrollment, TotpStore, TotpStoreError,
    TwoFaAttemptId, TwoFaCode, TwoFaCodeStore, TwoFaCodeStoreError, TwoFaError, User, UserError,
    UserStore, UserStoreError, ValidatedUser, WebAuthnVerifier,
    strategies::authenticator::{
        AuthenticationScheme, LoginOutcome, SupportsRegistration, SupportsTwoFactor,
    },
};
use thiserror::Error;

use crate::authentication::deferred::Deferred;
use crate::authentication::token_strategy::{ACCOUNT_BUSY, TokenStrategy, UserLock};
use crate::authentication::totp::{self, Totp, TotpFactor};
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
///
/// Web frameworks clone the scheme for every request, so a clone must be
/// cheap: the scheme's own configuration is shared behind `Arc`s, and the
/// stores you pass in should be handles too (a connection pool, an
/// `Arc`-wrapped map), as every store in this crate is.
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
    /// Rate limits on the routes, when turned on (see [`Self::rate_limited`]).
    rate_limit: Option<crate::authentication::rate_limit::RateLimiter>,
    /// Extra rules for new passwords (see [`Self::password_policy`]).
    password_policy: Option<Arc<dyn tempered_core::PasswordPolicy>>,
    /// Where users' own API keys live, when they may manage them (see
    /// [`Self::supports_api_key_management`]).
    api_keys: Option<ApiKeyManagement>,
    /// Where an event for every library request goes (see
    /// [`Self::auth_events`]).
    events: Option<Arc<dyn crate::endpoints::AuthEventSink>>,
    /// The runner every slot's after-the-response jobs share (each slot
    /// has its own bound, from [`Deferred::for_slot`]).
    deferred: Deferred,
}

/// Users managing their own API keys: the store, and the scopes they may
/// give a key.
#[derive(Clone)]
pub(crate) struct ApiKeyManagement {
    store: Arc<dyn tempered_core::ApiKeyStore>,
    allowed_scopes: Arc<[String]>,
}

/// Authorization level a route requires.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Authz {
    /// A valid login session.
    #[default]
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
    /// What enrolling a passkey requires. The enrollment routes exist only
    /// when the scheme has passkeys (`supports_passkeys`); this decides which
    /// bucket they go in. Defaults to [`Authz::Login`].
    pub passkey_enrollment: Authz,
    /// What linking an OAuth provider while logged in requires. Defaults
    /// to [`Authz::Login`] (a verified address).
    pub oauth_linking: Authz,
}

// ============================================================================
// Capability slots (the "enabled" states for each optional capability)
// ============================================================================

/// Enabled two-factor slot: a code store plus the email client used to
/// deliver codes, and optionally TOTP (`P`, see
/// [`supports_totp`](CredentialScheme::supports_totp)). `()` is "email codes
/// only".
#[derive(Clone)]
pub struct TwoFa<T, E, P = ()> {
    store: T,
    email: E,
    totp: P,
    /// Passwordless login by mailed code, when turned on
    /// ([`supports_email_login`](CredentialScheme::supports_email_login)).
    email_login: Option<EmailLogin>,
}

/// Settings for passwordless login by email.
///
/// The codes live in a [`TwoFaCodeStore`] of their own, never the 2FA
/// slot's: a sign-in code must not be redeemable as a second factor at
/// `/verify-2fa`, and starting an email login must not replace (or spend
/// the attempts of) someone's pending 2FA challenge. With Redis, give it a
/// namespace: `RedisTwoFaCodeStore::new(conn).with_namespace("email_login")`.
#[derive(Clone)]
pub struct EmailLogin {
    store: Arc<dyn TwoFaCodeStore>,
    /// The app page a sign-in link opens; it reads `email`,
    /// `loginAttemptId` and `code` from the query and posts them to
    /// `/email-login/verify`. `None` mails the code only.
    link_base: Option<Arc<str>>,
    deferred: Deferred,
}

impl EmailLogin {
    /// Mail the code only, keeping codes in `store`.
    pub fn code(store: impl TwoFaCodeStore + 'static) -> Self {
        Self {
            store: Arc::new(store),
            link_base: None,
            deferred: Deferred::default(),
        }
    }

    /// Also mail a link to `page` (an absolute URL in your app) carrying the
    /// code. The page must post it: a link that logged in on `GET` would be
    /// used up by mail scanners that open links to check them.
    pub fn link(store: impl TwoFaCodeStore + 'static, page: impl Into<String>) -> Self {
        Self {
            store: Arc::new(store),
            link_base: Some(page.into().into()),
            deferred: Deferred::default(),
        }
    }
}

/// Enabled elevation ("sudo") slot: a *second* token strategy for short-lived
/// elevated tokens (a separate JWT config/secret, or a separate session store).
#[derive(Clone)]
pub struct Elevation<TE> {
    tokens: TE,
}

impl<T, E, P> TwoFa<T, E, P> {
    /// The TOTP part (`()` without TOTP), for the route table.
    pub(crate) fn totp(&self) -> &P {
        &self.totp
    }

    /// Whether passwordless login by email is on, for the route table.
    pub(crate) fn email_login_enabled(&self) -> bool {
        self.email_login.is_some()
    }
}

impl<U, T, S, E, P, L, R, M, O, K> CredentialScheme<U, T, TwoFa<S, E, P>, L, R, M, O, K> {
    /// Let users log in without a password: `/email-login/start` mails a
    /// six-digit code (and with [`EmailLogin::link`] a link carrying it),
    /// `/email-login/verify` logs in with it. The code has the 2FA code's
    /// single use, expiry and attempt budget; an account that requires 2FA
    /// is still asked for its second factor. Lights up
    /// [`SupportsEmailLogin`](tempered_core::SupportsEmailLogin).
    ///
    /// # Panics
    ///
    /// If the email-login store shares its codes with the 2FA store (the
    /// same in-memory store, or a Redis store in the same namespace): a
    /// sign-in code would then pass as a second factor.
    pub fn supports_email_login(mut self, mut settings: EmailLogin) -> Self
    where
        S: TwoFaCodeStore,
    {
        let two_fa = self.two_fa.store.keyspace();
        assert!(
            two_fa.is_none() || two_fa != settings.store.keyspace(),
            "the email-login code store shares the 2FA store's codes ({}); give it its own \
             store (with Redis: `.with_namespace(\"email_login\")`)",
            two_fa.unwrap_or_default()
        );
        settings.deferred = self.deferred.for_slot();
        self.two_fa.email_login = Some(settings);
        self
    }
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
    deferred: Deferred,
}

/// Enabled email-verification slot: a verification store plus the email client used to deliver links.
#[derive(Clone)]
pub struct EmailVerify<V, E> {
    store: V,
    email: E,
    deferred: Deferred,
}

/// Enabled OAuth2/OIDC slot: the authorization-code flow plus the cookie/redirect
/// settings the HTTP layer needs.
#[derive(Clone)]
pub struct OAuth<ST, ID, HC> {
    flow: OAuthFlow<ST, ID, HC>,
    // `Arc<str>`: the scheme is cloned per request, and these only change
    // while it is being built.
    state_cookie_name: Arc<str>,
    post_login_redirect: Arc<str>,
    two_fa_redirect: Arc<str>,
}

/// Enabled passkey (WebAuthn) slot: the credential ceremony flow.
#[derive(Clone)]
pub struct Passkeys<CS, ChS, V> {
    flow: PasskeyFlow<CS, ChS, V>,
    /// Whether a passkey login also asks a 2FA account for its code. See
    /// [`passkey_login_requires_2fa`](CredentialScheme::passkey_login_requires_2fa).
    requires_2fa: bool,
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

/// Removes a deleted user's provider links during `delete_account`. `()`
/// (OAuth not configured) has nothing to remove.
#[async_trait]
trait OAuthCleanup {
    async fn forget_user(&self, email: &Email) -> Result<(), OAuthFlowError>;
}

#[async_trait]
impl OAuthCleanup for () {
    async fn forget_user(&self, _email: &Email) -> Result<(), OAuthFlowError> {
        Ok(())
    }
}

#[async_trait]
impl<ST, ID, HC> OAuthCleanup for OAuth<ST, ID, HC>
where
    ST: OAuthStateStore + Send + Sync,
    ID: OAuthIdentityStore + Send + Sync,
    HC: OAuthHttpClient + Send + Sync,
{
    async fn forget_user(&self, email: &Email) -> Result<(), OAuthFlowError> {
        self.flow.forget_user(email).await
    }
}

/// What the email-verification capability knows about an account's address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressProof {
    /// The owner confirmed the address.
    Verified,
    /// Verification is offered and this address has not been confirmed.
    Unverified,
    /// The scheme has no email verification, so it cannot tell either way.
    Unknown,
}

/// Reads and clears the email-verification capability's proof of an account's
/// address. `()` (capability not configured) knows nothing and has nothing to
/// forget when the account is deleted.
#[async_trait]
trait EmailProof {
    async fn proof(&self, email: &Email) -> Result<AddressProof, EmailVerificationStoreError>;
    async fn forget(&self, email: &Email) -> Result<(), EmailVerificationStoreError>;
    /// Record that the address is proven by other means (a provider that
    /// vouches for it).
    async fn mark_verified(&self, email: &Email) -> Result<(), EmailVerificationStoreError>;
    /// Send a verification link, unless the address is already verified.
    async fn send_verification(&self, email: &Email) -> Result<(), VerificationSendError>;
    /// The mail a signup sends, after the response: a verification link to
    /// a `new_account`, otherwise a notice to the owner of the taken address.
    /// Signup answers the same either way, so the notice is how the owner
    /// (perhaps someone who forgot they had an account) learns of it, and
    /// deferring both keeps the response time from telling them apart.
    fn after_signup(&self, email: Email, new_account: bool);
}

/// Why a verification email could not be sent.
#[derive(Debug)]
enum VerificationSendError {
    Store(EmailVerificationStoreError),
    Email(String),
}

impl<TE: std::error::Error + Send + Sync + 'static> From<VerificationSendError>
    for CredentialError<TE>
{
    fn from(e: VerificationSendError) -> Self {
        match e {
            VerificationSendError::Store(e) => CredentialError::EmailVerificationStoreError(e),
            VerificationSendError::Email(e) => CredentialError::EmailError(e),
        }
    }
}

#[async_trait]
impl EmailProof for () {
    async fn proof(&self, _email: &Email) -> Result<AddressProof, EmailVerificationStoreError> {
        Ok(AddressProof::Unknown)
    }

    async fn forget(&self, _email: &Email) -> Result<(), EmailVerificationStoreError> {
        Ok(())
    }

    async fn mark_verified(&self, _email: &Email) -> Result<(), EmailVerificationStoreError> {
        Ok(())
    }

    async fn send_verification(&self, _email: &Email) -> Result<(), VerificationSendError> {
        Ok(())
    }

    fn after_signup(&self, _email: Email, _new_account: bool) {}
}

#[async_trait]
impl<V, E> EmailProof for EmailVerify<V, E>
where
    V: EmailVerificationTokenStore + Clone + Send + Sync + 'static,
    E: EmailClient + Clone + Send + Sync + 'static,
{
    async fn mark_verified(&self, email: &Email) -> Result<(), EmailVerificationStoreError> {
        self.store.mark_verified(email).await
    }

    async fn send_verification(&self, email: &Email) -> Result<(), VerificationSendError> {
        if self
            .store
            .is_verified(email)
            .await
            .map_err(VerificationSendError::Store)?
        {
            return Ok(());
        }
        let token = EmailVerificationToken::new();
        self.store
            .store_pending_verification(token.clone(), email.clone())
            .await
            .map_err(VerificationSendError::Store)?;
        self.email
            .send_mail(
                email,
                tempered_core::Mail::VerifyEmail {
                    token: token.to_string(),
                },
            )
            .await
            .map_err(VerificationSendError::Email)
    }

    fn after_signup(&self, email: Email, new_account: bool) {
        let this = self.clone();
        self.deferred.run("signup mail", async move {
            // The account exists either way: a failed link is logged and the
            // user can ask for another (`/verify-email/resend`).
            if new_account {
                if let Err(e) = this.send_verification(&email).await {
                    tracing::error!(error = ?e, "failed to send the verification email after signup");
                }
            } else if let Err(e) = this
                .email
                .send_mail(&email, tempered_core::Mail::AlreadyRegistered)
                .await
            {
                tracing::error!(error = ?e, "failed to send the already-registered notice");
            }
        });
    }

    async fn proof(&self, email: &Email) -> Result<AddressProof, EmailVerificationStoreError> {
        Ok(if self.store.is_verified(email).await? {
            AddressProof::Verified
        } else {
            AddressProof::Unverified
        })
    }

    async fn forget(&self, email: &Email) -> Result<(), EmailVerificationStoreError> {
        self.store.forget_email(email).await
    }
}

/// What a 2FA code authorises. It sets the email's subject, so the user can
/// tell a sign-in code from a code for a sensitive action they did not start.
#[derive(Clone, Copy, Debug)]
enum ChallengePurpose {
    SignIn,
    Elevation,
}

impl ChallengePurpose {
    fn mail(self, code: TwoFaCode) -> tempered_core::Mail {
        match self {
            ChallengePurpose::SignIn => tempered_core::Mail::SignInCode { code },
            ChallengePurpose::Elevation => tempered_core::Mail::ElevationCode { code },
        }
    }
}

/// Issues the 2FA challenge during `login`. `()` rejects (2FA not configured).
#[async_trait]
trait TwoFaChallenge {
    async fn issue_challenge(
        &self,
        email: &Email,
        purpose: ChallengePurpose,
    ) -> Result<TwoFaAttemptId, TwoFaChallengeError>;

    /// Drop a half-finished login for `email` (first factor accepted, code not
    /// yet entered). Called whenever the account's credentials are reset or
    /// the account is deleted: the first factor that login passed no longer
    /// stands. Succeeds when there is none.
    async fn cancel_pending(&self, email: &Email) -> Result<(), TwoFaChallengeError>;

    /// Redeem a code issued by [`issue_challenge`](Self::issue_challenge).
    async fn redeem(
        &self,
        email: &Email,
        attempt_id: &TwoFaAttemptId,
        code: &TwoFaCode,
    ) -> Result<(), TwoFaChallengeError>;

    /// Forget the user's second-factor data (account deletion). Unlike
    /// [`cancel_pending`](Self::cancel_pending) this removes enrolled
    /// authenticator apps, which a password change must keep.
    async fn forget_user(&self, _email: &Email) -> Result<(), TwoFaChallengeError> {
        Ok(())
    }
}

#[async_trait]
impl TwoFaChallenge for () {
    async fn issue_challenge(
        &self,
        _email: &Email,
        _purpose: ChallengePurpose,
    ) -> Result<TwoFaAttemptId, TwoFaChallengeError> {
        Err(TwoFaChallengeError::NotConfigured)
    }

    async fn cancel_pending(&self, _email: &Email) -> Result<(), TwoFaChallengeError> {
        Ok(())
    }

    async fn redeem(
        &self,
        _email: &Email,
        _attempt_id: &TwoFaAttemptId,
        _code: &TwoFaCode,
    ) -> Result<(), TwoFaChallengeError> {
        Err(TwoFaChallengeError::NotConfigured)
    }
}

#[async_trait]
impl<S, E, P> TwoFaChallenge for TwoFa<S, E, P>
where
    S: TwoFaCodeStore + Send + Sync,
    E: EmailClient + Send + Sync,
    P: TotpFactor,
{
    async fn issue_challenge(
        &self,
        email: &Email,
        purpose: ChallengePurpose,
    ) -> Result<TwoFaAttemptId, TwoFaChallengeError> {
        let attempt_id = TwoFaAttemptId::new();
        let code = TwoFaCode::new();

        // The attempt is recorded either way: it is what ties the second
        // step to this first one, and what counts wrong codes.
        self.store
            .store_code(email.clone(), attempt_id.clone(), code.clone())
            .await?;

        // An account with an authenticator app answers from the app; the
        // stored code is never sent, so only the app's code can match.
        if self.totp.uses_totp(email).await? {
            return Ok(attempt_id);
        }

        self.email
            .send_mail(email, purpose.mail(code.clone()))
            .await
            .map_err(TwoFaChallengeError::Email)?;

        Ok(attempt_id)
    }

    async fn cancel_pending(&self, email: &Email) -> Result<(), TwoFaChallengeError> {
        match self.store.delete(email).await {
            Ok(()) | Err(TwoFaCodeStoreError::UserNotFound) => {}
            Err(e) => return Err(e.into()),
        }
        // A pending email-login code is a way in that the reset must end
        // as well.
        if let Some(login) = &self.email_login {
            match login.store.delete(email).await {
                Ok(()) | Err(TwoFaCodeStoreError::UserNotFound) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    async fn redeem(
        &self,
        email: &Email,
        attempt_id: &TwoFaAttemptId,
        code: &TwoFaCode,
    ) -> Result<(), TwoFaChallengeError> {
        if !self.totp.uses_totp(email).await? {
            return Ok(self.store.redeem_code(email, attempt_id, code).await?);
        }
        // App code or recovery code. The code store still decides: it checks
        // the attempt id, counts the failure and consumes the attempt, so the
        // app path has the same attempt budget and single use as mailed
        // codes. It is handed the stored code when the app code is right and
        // a code that cannot match when it is wrong.
        let (_, stored) = self
            .store
            .get_login_attempt_id_and_two_fa_code(email)
            .await?;
        let presented = if self.totp.accept(email, code).await? {
            stored
        } else {
            never_matching(&stored)
        };
        Ok(self
            .store
            .redeem_code(email, attempt_id, &presented)
            .await?)
    }

    async fn forget_user(&self, email: &Email) -> Result<(), TwoFaChallengeError> {
        Ok(self.totp.forget(email).await?)
    }
}

/// A six-digit code different from `code` in its last digit.
fn never_matching(code: &TwoFaCode) -> TwoFaCode {
    let mut digits: Vec<u8> = code.as_bytes().to_vec();
    if let Some(last) = digits.last_mut() {
        *last = b'0' + (*last - b'0' + 1) % 10;
    }
    TwoFaCode::parse(String::from_utf8(digits).expect("digits are ASCII"))
        .expect("six digits stay six digits")
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
    #[error("TOTP store error: {0}")]
    Totp(#[from] TotpStoreError),
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
            TwoFaChallengeError::Totp(t) => CredentialError::TotpStoreError(t),
        }
    }
}

/// Exposes the elevated cookie name (if elevation is enabled) so `logout` can clear it.
pub(crate) trait ElevatedCookieName {
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

/// Revokes a user's elevated tokens wherever the primary ones are revoked
/// (password change, reset, deletion, securing an unproven account).
///
/// An elevated strategy may keep its own state: `SessionScheme`'s elevation
/// has its own session store, which revoking the primary sessions never
/// reaches. For JWT the two strategies share an epoch store, so this revokes
/// the same cutoff twice, which is harmless. `()` (no elevation) has nothing
/// to revoke.
#[async_trait]
pub(crate) trait ElevationRevoke {
    async fn revoke_all_elevated(&self, email: &Email) -> Result<(), ElevatedRevokeError>;
}

/// Drops a user's outstanding password-reset tokens wherever their tokens
/// are revoked. `()` (no password reset) has none.
#[async_trait]
trait ResetCleanup {
    async fn forget_resets(&self, email: &Email) -> Result<(), PasswordResetTokenStoreError>;
}

#[async_trait]
impl ResetCleanup for () {
    async fn forget_resets(&self, _email: &Email) -> Result<(), PasswordResetTokenStoreError> {
        Ok(())
    }
}

#[async_trait]
impl<P, E> ResetCleanup for PasswordReset<P, E>
where
    P: PasswordResetTokenStore + Send + Sync,
    E: Send + Sync,
{
    async fn forget_resets(&self, email: &Email) -> Result<(), PasswordResetTokenStoreError> {
        self.store.delete_all_for_user(email).await
    }
}

/// An elevated strategy's revocation error, boxed: its type is the elevation
/// slot's, not the scheme's primary token error.
pub type ElevatedRevokeError = Box<dyn std::error::Error + Send + Sync>;

#[async_trait]
impl ElevationRevoke for () {
    async fn revoke_all_elevated(&self, _email: &Email) -> Result<(), ElevatedRevokeError> {
        Ok(())
    }
}

#[async_trait]
impl<TE: TokenStrategy> ElevationRevoke for Elevation<TE> {
    async fn revoke_all_elevated(&self, email: &Email) -> Result<(), ElevatedRevokeError> {
        self.tokens
            .revoke_all_for_user(email)
            .await
            .map_err(|e| Box::new(e) as ElevatedRevokeError)
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

    /// Change the token strategy's settings (for strategy-specific builders
    /// such as `JwtScheme::supports_refresh_tokens`).
    pub(crate) fn map_tokens(mut self, f: impl FnOnce(T) -> T) -> Self {
        self.tokens = f(self.tokens);
        self
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
            rate_limit: None,
            password_policy: None,
            api_keys: None,
            events: None,
            deferred: Deferred::default(),
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
            two_fa: TwoFa {
                store,
                email,
                totp: (),
                email_login: None,
            },
            elevation: self.elevation,
            password_reset: self.password_reset,
            email_verify: self.email_verify,
            oauth: self.oauth,
            passkeys: self.passkeys,
            routes: self.routes,
            rate_limit: self.rate_limit,
            password_policy: self.password_policy,
            api_keys: self.api_keys,
            events: self.events,
            deferred: self.deferred,
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
        if caps.passkey_enrollment {
            self.routes.passkey_enrollment = Authz::Elevated;
        }
        if caps.oauth_linking {
            self.routes.oauth_linking = Authz::Elevated;
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
            rate_limit: self.rate_limit,
            password_policy: self.password_policy,
            api_keys: self.api_keys,
            events: self.events,
            deferred: self.deferred,
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
            password_reset: PasswordReset {
                store,
                email,
                deferred: self.deferred.for_slot(),
            },
            email_verify: self.email_verify,
            oauth: self.oauth,
            passkeys: self.passkeys,
            routes: self.routes,
            rate_limit: self.rate_limit,
            password_policy: self.password_policy,
            api_keys: self.api_keys,
            events: self.events,
            deferred: self.deferred,
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
            email_verify: EmailVerify {
                store,
                email,
                deferred: self.deferred.for_slot(),
            },
            oauth: self.oauth,
            passkeys: self.passkeys,
            routes: self.routes,
            rate_limit: self.rate_limit,
            password_policy: self.password_policy,
            api_keys: self.api_keys,
            events: self.events,
            deferred: self.deferred,
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
                state_cookie_name: DEFAULT_OAUTH_STATE_COOKIE.into(),
                post_login_redirect: "/".into(),
                two_fa_redirect: "/".into(),
            },
            passkeys: self.passkeys,
            routes: self.routes,
            rate_limit: self.rate_limit,
            password_policy: self.password_policy,
            api_keys: self.api_keys,
            events: self.events,
            deferred: self.deferred,
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
            passkeys: Passkeys {
                flow,
                requires_2fa: false,
            },
            routes: self.routes,
            rate_limit: self.rate_limit,
            password_policy: self.password_policy,
            api_keys: self.api_keys,
            events: self.events,
            deferred: self.deferred,
        }
    }
}

impl<U, T, F, L, R, M, O, CS, ChS, V> CredentialScheme<U, T, F, L, R, M, O, Passkeys<CS, ChS, V>> {
    /// Hold passkey logins to the account's second factor, like password
    /// logins: an account with 2FA gets a code after the passkey and is
    /// signed in once it enters it.
    ///
    /// Off by default. A passkey checked with user verification is already
    /// two factors (the device, plus the PIN or biometric that unlocks it),
    /// which is why most sites let it stand alone. Turn this on when a
    /// passkey alone is not enough for your accounts. It needs
    /// [`supports_2fa`](Self::supports_2fa): without it, a 2FA account
    /// cannot finish a passkey login, as with a password login.
    ///
    /// With it on, `/passkey/login/finish` answers a 2FA account with `206`
    /// and `{ "loginAttemptId", "email" }`. The email is there because a
    /// usernameless login never asked for one, and `/verify-2fa` takes both.
    pub fn passkey_login_requires_2fa(mut self) -> Self {
        self.passkeys.requires_2fa = true;
        self
    }
}

impl<U, T, F, L, R, M, ST, ID, HC, K> CredentialScheme<U, T, F, L, R, M, OAuth<ST, ID, HC>, K> {
    /// Override the cookie name used to bind the OAuth `state` to the browser
    /// (default [`DEFAULT_OAUTH_STATE_COOKIE`], `__Host-oauth_state`). Keep the
    /// `__Host-` prefix: it stops a sibling subdomain from planting its own
    /// state cookie, which would log the victim into the attacker's account.
    pub fn oauth_state_cookie(mut self, name: impl Into<String>) -> Self {
        self.oauth.state_cookie_name = name.into().into();
        self
    }

    /// Override where the browser is redirected after a successful OAuth callback
    /// (default `/`).
    pub fn oauth_post_login_redirect(mut self, path: impl Into<String>) -> Self {
        self.oauth.post_login_redirect = path.into().into();
        self
    }

    /// Override where the browser is redirected when an OAuth login reaches an
    /// account that requires two-factor authentication (default `/`).
    ///
    /// No session is issued on that redirect. The URL gets a single marker,
    /// `oauth_2fa=required`. What the page needs to call the 2FA verification
    /// route — the login attempt id and the email — is delivered in a
    /// short-lived `__Host-oauth_2fa` cookie instead of the URL, so it does not end
    /// up in server logs, browser history or `Referer` headers. The cookie is
    /// readable by the page's script (it is not `HttpOnly`) and holds a query
    /// string: `new URLSearchParams(value)` yields `loginAttemptId` and
    /// `email`. The page should delete it once read.
    pub fn oauth_two_fa_redirect(mut self, path: impl Into<String>) -> Self {
        self.oauth.two_fa_redirect = path.into().into();
        self
    }
}

impl<U, T, F, L, R, M, O, K> CredentialScheme<U, T, F, L, R, M, O, K> {
    /// Finalizer for readability; the scheme is already usable. Returns `self`.
    pub fn build(self) -> Self {
        self
    }

    /// Limit how often the routes an attacker would hammer (logins, 2FA,
    /// `/elevate`, password reset, verification mail) may be tried, per
    /// account and per client address. Over a limit a route answers `429`
    /// with `Retry-After`. See [`RateLimiter`](crate::authentication::rate_limit::RateLimiter)
    /// for the defaults and how the client address is found.
    pub fn rate_limited(mut self, limiter: crate::authentication::rate_limit::RateLimiter) -> Self {
        self.rate_limit = Some(limiter);
        self
    }

    /// Check every new password (signup, password change, reset) against
    /// `policy` too, beyond the length rule. A refused password is a `400`
    /// with the policy's message. See `BreachedPasswordCheck` (feature
    /// `breached-passwords`) for one built in.
    pub fn password_policy(mut self, policy: impl tempered_core::PasswordPolicy + 'static) -> Self {
        self.password_policy = Some(Arc::new(policy));
        self
    }

    /// Let users manage their own API keys: `GET /api-keys` lists them, and
    /// issuing (`POST`) and revoking (`DELETE /api-keys/{id}`) need an
    /// elevated token when the scheme has elevation (under `/elevated`), a
    /// verified address otherwise. Keys go into `store`, the one your
    /// [`ApiKeyScheme`](crate::authentication::api_key_scheme::ApiKeyScheme)
    /// validates against. Deleting the account deletes its keys.
    ///
    /// `allowed_scopes` are the only scopes a user may give their own key
    /// (a request for any other is refused): a scope is a permission, and
    /// users must not grant themselves ones they lack (say, `admin`). Keys
    /// with other scopes are for your own code to issue, with
    /// [`SupportsApiKeyIssuance`](tempered_core::SupportsApiKeyIssuance).
    pub fn supports_api_key_management<I, Sc>(
        mut self,
        store: impl tempered_core::ApiKeyStore + 'static,
        allowed_scopes: I,
    ) -> Self
    where
        I: IntoIterator<Item = Sc>,
        Sc: Into<String>,
    {
        self.api_keys = Some(ApiKeyManagement {
            store: Arc::new(store),
            allowed_scopes: allowed_scopes.into_iter().map(Into::into).collect(),
        });
        self
    }

    /// Report every library request to `sink` (route, status, account,
    /// client address): for an audit log, alerts on repeated failures, or
    /// a "new sign-in" email.
    pub fn auth_events(mut self, sink: impl crate::endpoints::AuthEventSink + 'static) -> Self {
        self.events = Some(Arc::new(sink));
        self
    }

    pub(crate) fn auth_event_sink(&self) -> Option<&Arc<dyn crate::endpoints::AuthEventSink>> {
        self.events.as_ref()
    }

    /// Run the after-the-response jobs (reset, signup and sign-in mails)
    /// with `runner` instead of `tokio::spawn`: your executor, tracking or
    /// job system. Applies to every slot, whenever it was added.
    pub fn deferred_runner(
        self,
        runner: impl crate::authentication::deferred::DeferredRunner + 'static,
    ) -> Self {
        self.deferred.set_runner(Arc::new(runner));
        self
    }

    /// The scopes users may give their own keys.
    pub(crate) fn allowed_api_key_scopes(&self) -> &[String] {
        self.api_keys.as_ref().map_or(&[], |m| &m.allowed_scopes)
    }

    /// Whether the scheme has elevation (for the route table).
    pub(crate) fn has_elevation(&self) -> bool
    where
        L: ElevatedCookieName,
    {
        self.elevation.elevated_cookie_name().is_some()
    }

    /// The API-key store, when users may manage their keys.
    pub(crate) fn api_key_store(&self) -> Option<&Arc<dyn tempered_core::ApiKeyStore>> {
        self.api_keys.as_ref().map(|m| &m.store)
    }

    /// Apply the password policy, if there is one.
    async fn check_new_password<TE>(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<(), CredentialError<TE>>
    where
        TE: std::error::Error + Send + Sync + 'static,
    {
        match &self.password_policy {
            Some(policy) => policy
                .check(email, password)
                .await
                .map_err(|e| CredentialError::PasswordRejected(e.0)),
            None => Ok(()),
        }
    }

    /// The rate limiter, if [`rate_limited`](Self::rate_limited) set one.
    pub fn rate_limiter(&self) -> Option<&crate::authentication::rate_limit::RateLimiter> {
        self.rate_limit.as_ref()
    }

    pub fn user_store(&self) -> &U {
        &self.user_store
    }

    /// The route intents (which always-on capabilities are exposed, at what level).
    /// Read by the delivery layer to auto-wire routes.
    pub fn route_flags(&self) -> &RouteFlags {
        &self.routes
    }

    /// The capability slots, in order: 2FA, elevation, password reset, email
    /// verification, OAuth, passkeys. For the route table
    /// (`crate::endpoints`), which asks each slot for its routes.
    pub(crate) fn slots(&self) -> (&F, &L, &R, &M, &O, &K) {
        (
            &self.two_fa,
            &self.elevation,
            &self.password_reset,
            &self.email_verify,
            &self.oauth,
            &self.passkeys,
        )
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
    passkey_enrollment: bool,
    oauth_linking: bool,
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

    /// Require elevation to enroll a passkey
    /// (`/elevated/passkey/register/{start,finish}`).
    ///
    /// A passkey is a durable login credential. With only a login session
    /// required, whoever holds a stolen session cookie could add their own
    /// passkey and keep access after the session ends; requiring a fresh
    /// re-authentication closes that. Takes effect when the scheme also has
    /// `supports_passkeys`, in either call order; logging in *with* a passkey
    /// is unaffected.
    pub fn supports_passkey_enrollment(mut self) -> Self {
        self.passkey_enrollment = true;
        self
    }

    /// Require an elevated token to link an OAuth provider to the account
    /// (`/elevated/oauth/{provider}/link`): a new way in, like a passkey.
    pub fn supports_oauth_linking(mut self) -> Self {
        self.oauth_linking = true;
        self
    }
}

impl<U, T, F, L, R, M, O, K> CredentialScheme<U, T, F, L, R, M, O, K>
where
    U: Send + Sync,
    T: TokenStrategy,
    F: Send + Sync,
    L: Send + Sync,
    R: Send + Sync,
    M: Send + Sync,
    O: Send + Sync,
    K: Send + Sync,
{
    /// Take the user's credential lock (see [`TokenStrategy::lock_user`]),
    /// waiting briefly if it is held: the work done under it is a few store
    /// calls, so it is normally free again within milliseconds.
    async fn lock_credentials(&self, email: &Email) -> Result<UserLock, CredentialError<T::Error>> {
        for attempt in 0..LOCK_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(LOCK_RETRY_DELAY).await;
            }
            if let Some(lock) = self
                .tokens
                .lock_user(email)
                .await
                .map_err(CredentialError::Token)?
            {
                return Ok(lock);
            }
        }
        Err(CredentialError::AccountBusy)
    }

    /// Release the lock. A failure is logged, not returned: the work under the
    /// lock has its own result, and the lock expires by itself.
    async fn unlock_credentials(&self, email: &Email, lock: UserLock) {
        if let Err(e) = self.tokens.unlock_user(email, lock).await {
            tracing::error!(error = %e, "failed to release the credential lock; it will expire");
        }
    }
}

// Private helper: the slot trait in the bound is internal by design.
#[allow(private_bounds)]
impl<U, T, F, L, R, M, O, K> CredentialScheme<U, T, F, L, R, M, O, K>
where
    T: TokenStrategy,
    L: ElevationRevoke + Sync,
    R: ResetCleanup + Sync,
{
    /// Void every token the user holds: primary and elevated, on every
    /// device, and any password-reset link still in their mailbox.
    async fn revoke_all_tokens(&self, email: &Email) -> Result<(), CredentialError<T::Error>> {
        self.tokens
            .revoke_all_for_user(email)
            .await
            .map_err(CredentialError::Token)?;
        self.elevation
            .revoke_all_elevated(email)
            .await
            .map_err(CredentialError::ElevatedToken)?;
        self.password_reset.forget_resets(email).await?;
        Ok(())
    }
}

#[allow(private_bounds)]
impl<U, T, F, L, R, M, O, K> CredentialScheme<U, T, F, L, R, M, O, K>
where
    T: TokenStrategy,
    L: ElevationRevoke + Sync,
{
    /// End the user's session with `handle` (a device log-out). Their
    /// elevated sessions end with it: one may belong to that device, the
    /// elevated tier asks for nothing else, and elevation is short-lived and
    /// easily taken again. `None` when the strategy keeps no session list.
    pub(crate) async fn end_device_session(
        &self,
        email: &Email,
        handle: &str,
    ) -> Option<Result<bool, CredentialError<T::Error>>> {
        let ended = match self.tokens.end_session(email, handle).await? {
            Ok(ended) => ended,
            Err(e) => return Some(Err(CredentialError::Token(e))),
        };
        if ended && let Err(e) = self.elevation.revoke_all_elevated(email).await {
            return Some(Err(CredentialError::ElevatedToken(e)));
        }
        Some(Ok(ended))
    }
}

impl<U, T, F, L, R, M, O, K> CredentialScheme<U, T, F, L, R, M, O, K>
where
    U: UserStore,
    T: TokenStrategy,
    F: Send + Sync,
    L: Send + Sync,
    R: Send + Sync,
    M: Send + Sync,
    O: Send + Sync,
    K: Send + Sync,
{
    /// Issue a key for the logged-in user `email`: only allowed scopes,
    /// and under the credential lock, so no key is issued for an account a
    /// deletion is removing.
    pub(crate) async fn issue_user_api_key(
        &self,
        email: Email,
        scopes: Vec<String>,
        expires_at: Option<u64>,
    ) -> Result<(tempered_core::ApiKeyId, String), CredentialError<T::Error>> {
        let Some(management) = &self.api_keys else {
            return Err(CredentialError::ApiKeys(
                "API key management is off".to_string(),
            ));
        };
        if let Some(scope) = scopes
            .iter()
            .find(|s| !management.allowed_scopes.contains(s))
        {
            return Err(CredentialError::ScopeNotAllowed(scope.clone()));
        }
        let lock = self.lock_credentials(&email).await?;
        let result = async {
            self.user_store.get_user(&email).await?;
            crate::authentication::api_key_scheme::issue_key(
                &*management.store,
                email.clone(),
                scopes,
                expires_at,
            )
            .await
            .map_err(|e| CredentialError::ApiKeys(e.to_string()))
        }
        .await;
        self.unlock_credentials(&email, lock).await;
        result
    }

    /// Delete the user's API keys, when users may manage them.
    async fn forget_api_keys(&self, email: &Email) -> Result<(), CredentialError<T::Error>> {
        match &self.api_keys {
            Some(management) => management
                .store
                .delete_all_for_owner(email)
                .await
                .map_err(|e| CredentialError::ApiKeys(e.to_string())),
            None => Ok(()),
        }
    }
}

const LOCK_ATTEMPTS: u32 = 20;
const LOCK_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

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
            LoginOutcome::Success(token) => {
                let mut builder = builder.status(200).cookie(&self.tokens.auth_cookie(&token));
                for cookie in self.tokens.extra_login_cookies(&token) {
                    builder = builder.cookie(&cookie);
                }
                let mut body = serde_json::json!({
                    "status": "success",
                    "message": "Login successful"
                });
                if let Some(serde_json::Value::Object(tokens)) = self.tokens.body_tokens(&token) {
                    body.as_object_mut()
                        .expect("the body is an object")
                        .extend(tokens);
                }
                builder.json_body(body).build()
            }
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

        let clear_cookie = crate::cookie_util::expired_cookie(&cookie_name);
        let mut builder = builder.status(200).cookie(&clear_cookie);
        for cookie in self.tokens.extra_logout_cookies() {
            builder = builder.cookie(&cookie);
        }

        // Also clear the elevated cookie, but only if elevation is enabled.
        let builder = match self.elevation.elevated_cookie_name() {
            Some(name) => builder.cookie(&crate::cookie_util::expired_cookie(name)),
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

        // The login opens before the credential is checked: see
        // `TokenStrategy::begin`.
        let ticket = self
            .tokens
            .begin(&email)
            .await
            .map_err(CredentialError::Token)?;
        let validated_user = self.user_store.authenticate_user(&email, &password).await?;

        match validated_user {
            ValidatedUser::Requires2Fa(email) => {
                // Delegate to the 2FA slot: issues + delivers the challenge, or
                // errors if the scheme was built without `supports_2fa`.
                let attempt_id = self
                    .two_fa
                    .issue_challenge(&email, ChallengePurpose::SignIn)
                    .await?;
                Ok(LoginOutcome::Requires2Fa { email, attempt_id })
            }
            ValidatedUser::No2Fa(email) => {
                let token = self
                    .tokens
                    .issue(&email, ticket)
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
    M: EmailProof + Clone + Send + Sync + 'static,
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
        // Depends on the password alone, not on whether the address is
        // taken, so it reveals nothing about accounts.
        self.check_new_password(&email, &password).await?;
        let user = User::new(email.clone(), password, data.requires_2fa);
        // A taken address answers exactly like a new one, so signup does not
        // tell anyone which addresses have accounts. The existing account is
        // untouched. The store hashes the password before it finds the
        // clash, and the mail either way goes out after the response, so the
        // two paths also take the same time.
        let new_account = match self.user_store.add_user(user).await {
            Ok(()) => true,
            Err(UserStoreError::UserAlreadyExists) => false,
            Err(e) => return Err(e.into()),
        };
        self.email_verify.after_signup(email, new_account);
        Ok(())
    }
}

#[async_trait]
impl<U, T, F, L, R, M, O, K> SupportsPasswordChange for CredentialScheme<U, T, F, L, R, M, O, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: ElevationRevoke + Clone + Send + Sync + 'static,
    R: ResetCleanup + Clone + Send + Sync + 'static,
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
        self.check_new_password(&email, &new_password).await?;
        self.user_store
            .set_new_password(&email, new_password)
            .await?;
        // A password change must strand whoever was holding the old password's
        // sessions — revoke every outstanding token (all devices).
        self.two_fa.cancel_pending(&email).await?;
        self.revoke_all_tokens(&email).await?;
        Ok(())
    }
}

#[async_trait]
impl<U, T, F, L, R, M, O, K> SupportsAccountDeletion for CredentialScheme<U, T, F, L, R, M, O, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: ElevationRevoke + Clone + Send + Sync + 'static,
    R: ResetCleanup + Clone + Send + Sync + 'static,
    M: EmailProof + Clone + Send + Sync + 'static,
    O: OAuthCleanup + Clone + Send + Sync + 'static,
    K: PasskeyCleanup + Clone + Send + Sync + 'static,
{
    type AccountDeletionError = CredentialError<T::Error>;

    #[tracing::instrument(name = "CredentialScheme::delete_account", skip(self))]
    async fn delete_account(&self, email: Email) -> Result<(), Self::AccountDeletionError> {
        // Under the credential lock: no login begins and no passkey is
        // enrolled for this user until the account is gone.
        let lock = self.lock_credentials(&email).await?;
        let result: Result<(), Self::AccountDeletionError> = async {
            // Order matters: everything that can log in as this user goes first,
            // the account last. If a step fails, what remains is an account with
            // fewer credentials — never credentials or sessions without an account.

            // Passkeys are a login credential for this account: remove them, so
            // they cannot outlive it or be inherited by a later account that
            // reuses the address.
            self.passkeys.forget_user(&email).await?;
            // So are its provider links, which also count as proof of the address.
            self.oauth.forget_user(&email).await?;
            // Proof that the address was verified belongs to this account, not to
            // the address: a later account that reuses it must prove it again.
            self.email_verify.forget(&email).await?;
            // An authenticator app enrolled for this account must not work
            // for a later account at the same address.
            self.two_fa.forget_user(&email).await?;
            // Nor may its API keys.
            self.forget_api_keys(&email).await?;
            // A deleted user's token would otherwise keep validating until it
            // expires (JWT validation is signature-based, not a user-store read).
            self.two_fa.cancel_pending(&email).await?;
            self.revoke_all_tokens(&email).await?;
            self.user_store.delete_user(&email).await?;
            // Both once more now that the account is gone. A password login that
            // began after the first pass, while the account still existed, may
            // have left a pending 2FA attempt or be about to get a token: the
            // attempt is cancelled and the token voided. A login that begins
            // after this finds no account.
            self.two_fa.cancel_pending(&email).await?;
            self.revoke_all_tokens(&email).await?;
            // And keys, in case one was issued as the account went.
            self.forget_api_keys(&email).await?;
            Ok(())
        }
        .await;
        self.unlock_credentials(&email, lock).await;
        result
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

// The capabilities, one module each.
mod elevation;
mod email_verification;
mod oauth;
mod passkeys;
mod password_reset;
mod two_factor;

pub use oauth::{DEFAULT_OAUTH_STATE_COOKIE, OAUTH_TWO_FA_COOKIE};

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

    #[error("The account is being updated")]
    AccountBusy,

    #[error("Elevated token error: {0}")]
    ElevatedToken(ElevatedRevokeError),

    #[error("TOTP store error: {0}")]
    TotpStoreError(#[from] TotpStoreError),

    /// Confirming or managing TOTP with nothing to act on: no enrolment
    /// started, or no authenticator app enabled.
    #[error("{0}")]
    TotpNotEnrolled(&'static str),

    #[error("API key store error: {0}")]
    ApiKeys(String),

    /// A user asked for a key with a scope they may not give it.
    #[error("Scope not allowed: {0}")]
    ScopeNotAllowed(String),

    /// Linking a provider that does not vouch for the account's address,
    /// to an account whose address is not proven.
    #[error("Verify your address before linking this provider")]
    AddressNotProven,

    /// The password policy refused the new password.
    #[error("{0}")]
    PasswordRejected(String),

    /// Email login for an account whose second factor is the inbox too.
    #[error("This account signs in with its password")]
    EmailLoginNotAllowed,
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
            // Distinct, safe-to-reveal signal: the account's guessing budget
            // is spent until the window ends; a new login does not refill it.
            CredentialError::TwoFaCodeStoreError(TwoFaCodeStoreError::TooManyAttempts) => (
                ErrorCategory::TooManyRequests,
                "Too many failed attempts; try again later".to_string(),
            ),
            // The store could not answer: the code was never checked, so
            // "invalid code" would send the user to retype a good one.
            CredentialError::TwoFaCodeStoreError(TwoFaCodeStoreError::UnexpectedError(e)) => {
                tracing::error!(error = %e, "2FA code store error");
                (ErrorCategory::Internal, "Internal error".to_string())
            }
            CredentialError::TwoFaCodeStoreError(_) => (
                ErrorCategory::Unauthorized,
                "Invalid or expired 2FA code".to_string(),
            ),
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

            CredentialError::AccountBusy => (ErrorCategory::Conflict, ACCOUNT_BUSY.to_string()),
            CredentialError::ElevatedToken(e) => {
                tracing::error!(error = %e, "elevated token revocation error");
                (ErrorCategory::Internal, "Internal error".to_string())
            }

            CredentialError::TotpStoreError(e) => {
                tracing::error!(error = %e, "TOTP store failed");
                (ErrorCategory::Internal, "Internal error".to_string())
            }
            CredentialError::TotpNotEnrolled(why) => (ErrorCategory::BadRequest, why.to_string()),
            CredentialError::PasswordRejected(why) => (ErrorCategory::BadRequest, why),
            CredentialError::ScopeNotAllowed(scope) => (
                ErrorCategory::BadRequest,
                format!("Scope not allowed: {scope}"),
            ),
            CredentialError::ApiKeys(e) => {
                tracing::error!(error = %e, "API key store error");
                (ErrorCategory::Internal, "Internal error".to_string())
            }
            CredentialError::AddressNotProven => (
                ErrorCategory::Forbidden,
                "Verify your address before linking this provider".to_string(),
            ),
            CredentialError::EmailLoginNotAllowed => (
                ErrorCategory::Forbidden,
                "This account signs in with its password".to_string(),
            ),
            CredentialError::OAuth(e) => e.classify(),
            CredentialError::Passkey(e) => e.classify(),
        }
    }
}
