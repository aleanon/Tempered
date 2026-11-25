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

/// The body of the mail a signup for a taken address sends its owner.
pub(crate) const ALREADY_REGISTERED_NOTICE: &str = "Someone tried to create an account with this \
email address, which already has one. If it was you, sign in, or reset your password if \
you have forgotten it. If it was not, you can ignore this message: nothing has changed.";

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
            .send_email(email, "Verify your email", &token.to_string())
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
                .send_email(
                    &email,
                    "You already have an account",
                    ALREADY_REGISTERED_NOTICE,
                )
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
    fn subject(self) -> &'static str {
        match self {
            ChallengePurpose::SignIn => "Your sign-in code",
            ChallengePurpose::Elevation => "Code to confirm a sensitive account action",
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
            .send_email(email, purpose.subject(), code.as_str())
            .await
            .map_err(TwoFaChallengeError::Email)?;

        Ok(attempt_id)
    }

    async fn cancel_pending(&self, email: &Email) -> Result<(), TwoFaChallengeError> {
        match self.store.delete(email).await {
            Ok(()) | Err(TwoFaCodeStoreError::UserNotFound) => Ok(()),
            Err(e) => Err(e.into()),
        }
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

/// Revokes a user's elevated tokens wherever the primary ones are revoked
/// (password change, reset, deletion, securing an unproven account).
///
/// An elevated strategy may keep its own state: `SessionScheme`'s elevation
/// has its own session store, which revoking the primary sessions never
/// reaches. For JWT the two strategies share an epoch store, so this revokes
/// the same cutoff twice, which is harmless. `()` (no elevation) has nothing
/// to revoke.
#[async_trait]
trait ElevationRevoke {
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
            },
            elevation: self.elevation,
            password_reset: self.password_reset,
            email_verify: self.email_verify,
            oauth: self.oauth,
            passkeys: self.passkeys,
            routes: self.routes,
            rate_limit: self.rate_limit,
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
                deferred: Deferred::default(),
            },
            email_verify: self.email_verify,
            oauth: self.oauth,
            passkeys: self.passkeys,
            routes: self.routes,
            rate_limit: self.rate_limit,
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
                deferred: Deferred::default(),
            },
            oauth: self.oauth,
            passkeys: self.passkeys,
            routes: self.routes,
            rate_limit: self.rate_limit,
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

        let clear_cookie = crate::cookie_util::expired_cookie(&cookie_name);
        let builder = builder.status(200).cookie(&clear_cookie);

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

// ============================================================================
// Two-Factor Authentication (gated on the `TwoFa` slot)
// ============================================================================

#[async_trait]
impl<U, T, S, E, P, L, R, M, O, K> SupportsTwoFactor
    for CredentialScheme<U, T, TwoFa<S, E, P>, L, R, M, O, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    S: TwoFaCodeStore + Clone + Send + Sync + 'static,
    E: EmailClient + Clone + Send + Sync + 'static,
    P: TotpFactor + Clone + 'static,
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
        let ticket = self
            .tokens
            .begin(&email)
            .await
            .map_err(CredentialError::Token)?;
        // Checks and consumes the code in one step: two concurrent requests
        // with the right code cannot both get past it.
        self.two_fa.redeem(&email, &attempt_id, &code).await?;
        // The account may have been deleted since the first factor.
        self.user_store.get_user(&email).await?;
        Ok(self
            .tokens
            .issue(&email, ticket)
            .await
            .map_err(CredentialError::Token)?)
    }
}

// ============================================================================
// TOTP (on the 2FA slot; needs elevation for its routes)
// ============================================================================

impl<U, T, S, E, TE, R, M, O, K> CredentialScheme<U, T, TwoFa<S, E>, Elevation<TE>, R, M, O, K> {
    /// Let users add an authenticator app (TOTP) as their second factor,
    /// with recovery codes, lighting up [`SupportsTotp`] and its routes
    /// (`/elevated/totp/...`, elevated tier: adding or removing a second
    /// factor needs a fresh re-authentication). `issuer` is the name the
    /// app shows next to the account. Needs [`supports_2fa`](Self::supports_2fa)
    /// and elevation first.
    ///
    /// An account with an app gets no mailed code at login: its 2FA step
    /// takes the app's code or a recovery code, in the same `2FACode` field.
    // The return type spells out every capability slot on purpose: it is the
    // typestate transition.
    #[allow(clippy::type_complexity)]
    pub fn supports_totp<TS>(
        self,
        store: TS,
        issuer: impl Into<String>,
    ) -> CredentialScheme<U, T, TwoFa<S, E, Totp<TS>>, Elevation<TE>, R, M, O, K> {
        CredentialScheme {
            user_store: self.user_store,
            tokens: self.tokens,
            two_fa: TwoFa {
                store: self.two_fa.store,
                email: self.two_fa.email,
                totp: Totp::new(store, issuer),
            },
            elevation: self.elevation,
            password_reset: self.password_reset,
            email_verify: self.email_verify,
            oauth: self.oauth,
            passkeys: self.passkeys,
            routes: self.routes,
            rate_limit: self.rate_limit,
        }
    }
}

#[async_trait]
impl<U, T, S, E, TS, L, R, M, O, K> SupportsTotp
    for CredentialScheme<U, T, TwoFa<S, E, Totp<TS>>, L, R, M, O, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    S: TwoFaCodeStore + Clone + Send + Sync + 'static,
    E: EmailClient + Clone + Send + Sync + 'static,
    TS: TotpStore + Clone + 'static,
    L: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    K: Clone + Send + Sync + 'static,
{
    type TotpError = CredentialError<T::Error>;

    async fn start_totp(&self, email: Email) -> Result<TotpEnrollment, Self::TotpError> {
        let totp = &self.two_fa.totp;
        let secret = totp::new_secret();
        let enrollment = TotpEnrollment {
            secret: Secret::new(totp::base32(secret.expose_secret())),
            otpauth_uri: Secret::new(totp::otpauth_uri(
                &totp.issuer,
                &email,
                secret.expose_secret(),
            )),
        };
        totp.store.set_pending(&email, secret).await?;
        Ok(enrollment)
    }

    async fn confirm_totp(
        &self,
        email: Email,
        code: TwoFaCode,
    ) -> Result<Vec<String>, Self::TotpError> {
        let store = &self.two_fa.totp.store;
        let Some(pending) = store.pending(&email).await? else {
            return Err(CredentialError::TotpNotEnrolled(
                "Start adding an authenticator app first",
            ));
        };
        let Some(step) = totp::matching_step(pending.expose_secret(), &code, totp::unix_now())
        else {
            return Err(TwoFaCodeStoreError::Invalid2FACode.into());
        };
        let (shown, hashes) = totp::new_recovery_codes();
        if !store.activate(&email, step, hashes).await? {
            return Err(CredentialError::TotpNotEnrolled(
                "Start adding an authenticator app first",
            ));
        }
        // The app is the second factor now, so 2FA is on.
        self.user_store.set_requires_2fa(&email, true).await?;
        Ok(shown)
    }

    async fn disable_totp(&self, email: Email) -> Result<(), Self::TotpError> {
        Ok(self.two_fa.totp.store.delete_all_for_user(&email).await?)
    }

    async fn regenerate_recovery_codes(
        &self,
        email: Email,
    ) -> Result<Vec<String>, Self::TotpError> {
        let store = &self.two_fa.totp.store;
        if store.active(&email).await?.is_none() {
            return Err(CredentialError::TotpNotEnrolled(
                "No authenticator app is enabled",
            ));
        }
        let (shown, hashes) = totp::new_recovery_codes();
        store.replace_recovery_codes(&email, hashes).await?;
        Ok(shown)
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
    ) -> Result<LoginOutcome<Self::ElevatedToken>, Self::ElevationError> {
        // Re-authenticate, then mint a token via the *elevated* strategy.
        let ticket = self
            .elevation
            .tokens
            .begin(&email)
            .await
            .map_err(CredentialError::Token)?;
        match self.user_store.authenticate_user(&email, &password).await? {
            // The second factor guards sudo as it guards login: a password
            // alone (say, phished, plus a stolen session) must not reach the
            // elevated routes. Fails closed without the 2FA capability.
            ValidatedUser::Requires2Fa(email) => {
                let attempt_id = self
                    .two_fa
                    .issue_challenge(&email, ChallengePurpose::Elevation)
                    .await?;
                Ok(LoginOutcome::Requires2Fa { email, attempt_id })
            }
            ValidatedUser::No2Fa(email) => Ok(LoginOutcome::Success(
                self.elevation
                    .tokens
                    .issue(&email, ticket)
                    .await
                    .map_err(CredentialError::Token)?,
            )),
        }
    }

    #[tracing::instrument(name = "CredentialScheme::verify_elevation_2fa", skip(self, code))]
    async fn verify_elevation_2fa(
        &self,
        email: Email,
        attempt_id: TwoFaAttemptId,
        code: TwoFaCode,
    ) -> Result<Self::ElevatedToken, Self::ElevationError> {
        let ticket = self
            .elevation
            .tokens
            .begin(&email)
            .await
            .map_err(CredentialError::Token)?;
        self.two_fa.redeem(&email, &attempt_id, &code).await?;
        // The account may have been deleted since the first factor.
        self.user_store.get_user(&email).await?;
        Ok(self
            .elevation
            .tokens
            .issue(&email, ticket)
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
        outcome: LoginOutcome<Self::ElevatedToken>,
    ) -> Result<RB::Response, tempered_core::ResponseBuilderError> {
        match outcome {
            LoginOutcome::Success(elevated_token) => builder
                .status(200)
                .cookie(&self.elevation.tokens.auth_cookie(&elevated_token))
                .json_body(serde_json::json!({
                    "status": "elevated",
                    "message": "Elevation successful"
                }))
                .build(),
            // Same shape as a 2FA login: the code was sent, and
            // `/elevate/verify-2fa` takes it with this attempt id.
            LoginOutcome::Requires2Fa { attempt_id, .. } => builder
                .status(206)
                .json_body(serde_json::json!({
                    "status": "requires_2fa",
                    "message": "2FA required",
                    "loginAttemptId": attempt_id.to_string()
                }))
                .build(),
        }
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
    L: ElevationRevoke + Clone + Send + Sync + 'static,
    P: PasswordResetTokenStore + Clone + Send + Sync + 'static,
    E: EmailClient + Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    K: Clone + Send + Sync + 'static,
{
    type PasswordResetError = CredentialError<T::Error>;

    #[tracing::instrument(name = "CredentialScheme::initiate_password_reset", skip(self))]
    async fn initiate_password_reset(&self, email: Email) -> Result<(), Self::PasswordResetError> {
        // Everything that depends on whether the account exists happens
        // after the response, so neither the answer nor its timing says
        // which addresses are registered (see `deferred`). Failures are
        // logged; the caller would not have been told either way.
        let users = self.user_store.clone();
        let reset = self.password_reset.clone();
        self.password_reset
            .deferred
            .run("password reset mail", async move {
                match users.get_user(&email).await {
                    Ok(_) => {}
                    Err(UserStoreError::UserNotFound) => return,
                    Err(e) => {
                        tracing::error!(error = ?e, "password reset: user lookup failed");
                        return;
                    }
                }
                let token = PasswordResetToken::new();
                if let Err(e) = reset.store.store_token(token.clone(), email.clone()).await {
                    tracing::error!(error = ?e, "password reset: failed to store the token");
                    return;
                }
                if let Err(e) = reset
                    .email
                    .send_email(&email, "Password Reset", &token.to_string())
                    .await
                {
                    tracing::error!(error = e, "password reset: failed to send the mail");
                }
            });
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
            .map_err(|e| match e {
                PasswordResetTokenStoreError::TokenNotFound => CredentialError::InvalidResetToken,
                // An outage is not a bad link: report it (as a 500) rather
                // than tell the user their link is invalid.
                e => CredentialError::PasswordResetTokenStoreError(e),
            })?;

        self.user_store
            .set_new_password(&email, new_password)
            .await?;

        // A reset is a password change — typically *because* the account may
        // be compromised — so strand every outstanding session.
        self.two_fa.cancel_pending(&email).await?;
        self.revoke_all_tokens(&email).await?;

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
        // Nothing is sent for an address that is already verified.
        Ok(self.email_verify.send_verification(&email).await?)
    }

    #[tracing::instrument(name = "CredentialScheme::verify_email", skip(self, token))]
    async fn verify_email(
        &self,
        email: &Email,
        token: String,
    ) -> Result<(), Self::EmailVerificationError> {
        let token = EmailVerificationToken::parse(&token)
            .ok_or(CredentialError::InvalidVerificationToken)?;

        let sent_to = self
            .email_verify
            .store
            .consume_token(&token)
            .await
            .map_err(|_| CredentialError::InvalidVerificationToken)?;
        // Answered exactly like an unknown token: the caller learns nothing
        // about whose token it was.
        if &sent_to != email {
            return Err(CredentialError::InvalidVerificationToken);
        }

        self.email_verify.store.mark_verified(email).await?;
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
    L: ElevationRevoke + Clone + Send + Sync + 'static,
    R: ResetCleanup + Clone + Send + Sync + 'static,
    M: EmailProof + Clone + Send + Sync + 'static,
    ST: OAuthStateStore + Clone + Send + Sync + 'static,
    ID: OAuthIdentityStore + Clone + Send + Sync + 'static,
    HC: OAuthHttpClient + Clone + Send + Sync + 'static,
    K: PasskeyCleanup + Clone + Send + Sync + 'static,
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
        // The flow proves who is at the provider; nothing is linked yet.
        let identity = self
            .oauth
            .flow
            .complete(provider, code, query_state, cookie_state)
            .await?;
        let email = identity.email().clone();

        // From here it is an ordinary login to that email's account, creating
        // the account first if this is the user's first visit.
        if !identity.already_linked() {
            self.prepare_account_for_first_link(&email).await?;
            // Linked last: if anything above failed, the next attempt starts
            // from an unlinked identity and secures the account again.
            self.oauth.flow.link(&identity).await?;
        }

        // The login opens once the account is in its final state (securing it
        // revokes its sessions, which would void an earlier ticket), and
        // before the account is read: a deletion from here on is caught.
        let ticket = self
            .tokens
            .begin(&email)
            .await
            .map_err(CredentialError::Token)?;
        // When the provider vouches for the address (it reported this one,
        // verified), the account now counts as proven. It does not once the
        // user changed their address at the provider: the identity still
        // logs in, but proves nothing about the old address. Under the
        // credential lock, so a deletion cannot clear the mark between the
        // link check and the write and leave it behind for the next account
        // at this address.
        let lock = self.lock_credentials(&email).await?;
        let marked: Result<(), CredentialError<T::Error>> = async {
            if !self.oauth.flow.is_linked(&identity).await? {
                // Unlinked since it was verified: the account was deleted.
                return Err(UserStoreError::UserNotFound.into());
            }
            if identity.vouches_for_email() {
                self.email_verify.mark_verified(&email).await?;
            }
            Ok(())
        }
        .await;
        self.unlock_credentials(&email, lock).await;
        marked?;
        let requires_2fa = self.user_store.get_user(&email).await?.requires_2fa;

        if requires_2fa {
            // The provider stands in for the password, not for the second
            // factor. Same path as password login: issue + deliver the
            // challenge, or error if the scheme was built without 2FA.
            let attempt_id = self
                .two_fa
                .issue_challenge(&email, ChallengePurpose::SignIn)
                .await?;
            return Ok(LoginOutcome::Requires2Fa { email, attempt_id });
        }

        let token = self
            .tokens
            .issue(&email, ticket)
            .await
            .map_err(CredentialError::Token)?;
        Ok(LoginOutcome::Success(token))
    }
}

// Private helpers: the slot traits in the bounds are internal by design.
#[allow(private_bounds)]
impl<U, T, F, L, R, M, ST, ID, HC, K> CredentialScheme<U, T, F, L, R, M, OAuth<ST, ID, HC>, K>
where
    U: UserStore,
    T: TokenStrategy,
    M: EmailProof + Send + Sync,
    ST: OAuthStateStore + Send + Sync,
    ID: OAuthIdentityStore + Send + Sync,
    HC: OAuthHttpClient + Send + Sync,
    K: PasskeyCleanup + Send + Sync,
    F: TwoFaChallenge + Send + Sync,
    L: ElevationRevoke + Send + Sync,
    R: ResetCleanup + Send + Sync,
{
    /// Get `email`'s account ready for the first login through a provider
    /// identity that is not linked to it yet.
    ///
    /// - No account: create one. The user store requires a password, so it gets
    ///   a random one nobody knows; the user signs in through the provider and
    ///   can set a real password through password reset.
    /// - An account whose address is already proven: left untouched.
    /// - An account whose address was never proven: secured first, see
    ///   [`secure_unproven_account`](Self::secure_unproven_account).
    async fn prepare_account_for_first_link(
        &self,
        email: &Email,
    ) -> Result<(), CredentialError<T::Error>> {
        match self.user_store.get_user(email).await {
            Ok(_) => {}
            Err(UserStoreError::UserNotFound) => {
                let user = User::new(email.clone(), unknowable_password(), false);
                match self.user_store.add_user(user).await {
                    Ok(()) => return Ok(()),
                    // Lost a race with a signup for the same address. That
                    // account is as unproven as any other: fall through.
                    Err(UserStoreError::UserAlreadyExists) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) => return Err(e.into()),
        }

        let proof = self.email_verify.proof(email).await?;
        let proven =
            proof == AddressProof::Verified || self.oauth.flow.has_linked_identity(email).await?;
        if proven {
            return Ok(());
        }

        // The 2FA requirement is dropped only when the scheme positively knows
        // the address was never confirmed. Without email verification every
        // signup account looks unproven, and most of them are genuine: their
        // owners keep the second factor they chose.
        let drop_two_fa = proof == AddressProof::Unverified;
        self.secure_unproven_account(email, drop_two_fa).await
    }

    /// Remove every way into an account that predates proof of its address.
    ///
    /// Signup does not prove the address belongs to whoever signed up, so an
    /// attacker can register a victim's address and wait for the victim to
    /// arrive through a provider ("account pre-hijacking"). Whoever created
    /// this account may still hold its password, a session, or a passkey: all
    /// three go before the provider's user is let in. A genuine user who
    /// signed up with a password loses it and sets a new one via password
    /// reset.
    ///
    /// With `drop_two_fa`, the account's 2FA requirement goes too: it was
    /// chosen by whoever signed up, and the owner should not be held to a
    /// second factor they did not set up (or cannot pass).
    ///
    /// It all happens under the user's credential lock, so one credential
    /// cannot mint another while this runs: no login begins, and a session
    /// that is about to be revoked cannot enrol a passkey (enrolment takes the
    /// same lock, and enrolments already started are dropped with the
    /// passkeys). The order and the second passkey pass are what remains if
    /// the lock expires under a stalled store: password first (no new password
    /// logins), then passkeys, then sessions, then passkeys once more.
    async fn secure_unproven_account(
        &self,
        email: &Email,
        drop_two_fa: bool,
    ) -> Result<(), CredentialError<T::Error>> {
        let lock = self.lock_credentials(email).await?;
        let result: Result<(), CredentialError<T::Error>> = async {
            self.user_store
                .set_new_password(email, unknowable_password())
                .await?;
            if drop_two_fa {
                self.user_store.set_requires_2fa(email, false).await?;
            }
            self.passkeys.forget_user(email).await?;
            self.two_fa.cancel_pending(email).await?;
            self.revoke_all_tokens(email).await?;
            self.passkeys.forget_user(email).await?;
            Ok(())
        }
        .await;
        self.unlock_credentials(email, lock).await;
        result
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
    L: ElevatedCookieName + ElevationRevoke + Clone + Send + Sync + 'static,
    R: ResetCleanup + Clone + Send + Sync + 'static,
    M: EmailProof + Clone + Send + Sync + 'static,
    ST: OAuthStateStore + Clone + Send + Sync + 'static,
    ID: OAuthIdentityStore + Clone + Send + Sync + 'static,
    HC: OAuthHttpClient + Clone + Send + Sync + 'static,
    K: PasskeyCleanup + Clone + Send + Sync + 'static,
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
        let clear_state = crate::cookie_util::expired_cookie(&self.oauth.state_cookie_name);
        let builder = builder.status(302).cookie(&clear_state);

        match outcome {
            // Deliver the issued token exactly as login does and enter the app.
            LoginOutcome::Success(token) => builder
                .cookie(&self.tokens.auth_cookie(&token))
                .header("location", &self.oauth.post_login_redirect)
                .build(),
            // No token yet: send the browser to the app's second-factor step.
            // What it needs to call the 2FA verification route travels in a
            // short-lived cookie, not the URL (see `oauth_two_fa_redirect`).
            LoginOutcome::Requires2Fa { email, attempt_id } => builder
                .cookie(&two_fa_handoff_cookie(&email, &attempt_id))
                .header("location", &with_two_fa_marker(&self.oauth.two_fa_redirect))
                .build(),
        }
    }
}

/// The OAuth state cookie's default name. The `__Host-` prefix makes the
/// browser refuse the cookie unless it is `Secure`, has `Path=/` and no
/// `Domain`, so only this exact host can set it: a sibling subdomain cannot
/// plant a state of its own (cookie tossing) and so cannot complete its own
/// provider login in the victim's browser.
pub const DEFAULT_OAUTH_STATE_COOKIE: &str = "__Host-oauth_state";

/// Name of the cookie that hands a pending OAuth 2FA login to the page. The
/// `__Host-` prefix keeps a sibling subdomain from planting a hand-off of its
/// own, as for [`DEFAULT_OAUTH_STATE_COOKIE`].
pub const OAUTH_TWO_FA_COOKIE: &str = "__Host-oauth_2fa";

/// The hand-off cookie: `loginAttemptId` and `email` as a query string.
///
/// Deliberately not `HttpOnly`: the page's script must read it to call the 2FA
/// verification route, exactly as it reads the attempt id from the JSON body
/// after a password login. Neither value is a credential — the attempt id is
/// useless without the emailed code. `Max-Age` matches the OAuth state cookie.
fn two_fa_handoff_cookie(email: &Email, attempt_id: &TwoFaAttemptId) -> String {
    let value = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("loginAttemptId", &attempt_id.to_string())
        .append_pair("email", email.as_ref().expose_secret())
        .finish();
    format!("{OAUTH_TWO_FA_COOKIE}={value}; Secure; SameSite=Lax; Path=/; Max-Age=600")
}

/// `base` with `oauth_2fa=required` added to its query string, keeping any
/// query or fragment `base` already has.
fn with_two_fa_marker(base: &str) -> String {
    let (path_and_query, fragment) = match base.split_once('#') {
        Some((before, after)) => (before, Some(after)),
        None => (base, None),
    };
    let separator = if path_and_query.contains('?') {
        '&'
    } else {
        '?'
    };
    let mut location = format!("{path_and_query}{separator}oauth_2fa=required");
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
        // Storing a credential and removing a user's credentials exclude each
        // other. The session that authorised this request may have been
        // revoked since the middleware checked it; if so, the same cleanup
        // dropped the ceremony, and the flow finds none under the lock.
        let lock = self.lock_credentials(&email).await?;
        let result = self
            .passkeys
            .flow
            .finish_registration(&email, ceremony_id, response)
            .await;
        self.unlock_credentials(&email, lock).await;
        result?;
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
    ) -> Result<LoginOutcome<Self::Token>, Self::PasskeyError> {
        let (email, credential_id) = self
            .passkeys
            .flow
            .finish_authentication_with_credential(ceremony_id, response)
            .await?;
        // Only the credential says whose login this is, so the login opens
        // here and the credential is confirmed again after it: removed in
        // between, it fails; removed later, the ticket catches it.
        let ticket = self
            .tokens
            .begin(&email)
            .await
            .map_err(CredentialError::Token)?;
        self.passkeys
            .flow
            .confirm_enrolled(&email, &credential_id)
            .await?;
        // A passkey outlives nothing: if the account it was enrolled for is gone
        // (deleted since enrollment), the credential must not mint a session.
        let user = self.user_store.get_user(&email).await?;
        if self.passkeys.requires_2fa && user.requires_2fa() {
            let attempt_id = self
                .two_fa
                .issue_challenge(&email, ChallengePurpose::SignIn)
                .await?;
            return Ok(LoginOutcome::Requires2Fa { email, attempt_id });
        }
        Ok(LoginOutcome::Success(
            self.tokens
                .issue(&email, ticket)
                .await
                .map_err(CredentialError::Token)?,
        ))
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
            CredentialError::OAuth(e) => e.classify(),
            CredentialError::Passkey(e) => e.classify(),
        }
    }
}
