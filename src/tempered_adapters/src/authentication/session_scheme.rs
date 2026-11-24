//! Opaque server-side session scheme — the session specialization of
//! [`CredentialScheme`](crate::authentication::credential_scheme::CredentialScheme).
//!
//! `SessionScheme` is a type alias over `CredentialScheme<U, SessionTokens<S>, …>`:
//! it is the same credential scheme as [`JwtScheme`](crate::authentication::jwt_scheme::JwtScheme),
//! just with the stateful [`SessionTokens`] strategy plugged in — so it inherits
//! the whole capability suite (2FA, elevation, registration, password reset,
//! email verification, OAuth, passkeys). Login verifies the password, creates a
//! server-side session in a [`SessionStore`], and returns the random
//! [`SessionId`] in an HttpOnly cookie; because the session lives server-side,
//! logout (or any revocation) invalidates it instantly.
//!
//! Note: unlike the previous standalone scheme, a 2FA-flagged user logging into a
//! session scheme *without* `supports_2fa` now errors (consistent with JWT)
//! rather than being granted a session immediately.

use std::sync::Arc;

use crate::cookie_util::cookie_value;
use async_trait::async_trait;
use tempered_core::{
    AuthRequest, AuthValidator, ClassifyError, Email, ErrorCategory, SessionId, SessionRecord,
    SessionStore, SessionStoreError, UserStore,
};
use thiserror::Error;

use crate::authentication::credential_scheme::{CredentialScheme, ElevatedCapabilities, Elevation};
use crate::authentication::token_strategy::{
    ACCOUNT_BUSY, TokenStrategy, USER_LOCK_TTL_SECONDS, UserLock,
};

// ============================================================================
// Configuration
// ============================================================================

/// How long a session may live, however often it is used, unless the
/// config says otherwise: 24 hours, so a user signs in about once a day.
pub const DEFAULT_MAX_SESSION_LIFETIME_SECONDS: u64 = 24 * 60 * 60;

#[derive(Clone)]
pub struct SessionConfig {
    /// The auth cookie's name. Prefer one starting with `__Host-` (e.g.
    /// `__Host-session`): the browser then accepts the cookie only from this
    /// exact host, so a sibling subdomain cannot overwrite it with a session
    /// of its own. The cookies this crate sets already meet the prefix's
    /// rules (`Secure`, `Path=/`, no `Domain`).
    pub cookie_name: String,
    /// Idle timeout: a session unused this long expires. Every request
    /// restarts it (sliding expiry).
    pub ttl_in_seconds: u64,
    /// Absolute lifetime: a session this old expires even if it is in use.
    /// Caps how long a stolen session cookie stays good.
    pub max_lifetime_in_seconds: u64,
}

impl SessionConfig {
    /// A config with the default absolute lifetime
    /// ([`DEFAULT_MAX_SESSION_LIFETIME_SECONDS`]).
    pub fn new(cookie_name: impl Into<String>, ttl_in_seconds: u64) -> Self {
        Self {
            cookie_name: cookie_name.into(),
            ttl_in_seconds,
            max_lifetime_in_seconds: DEFAULT_MAX_SESSION_LIFETIME_SECONDS,
        }
    }

    /// Set the absolute lifetime.
    pub fn max_lifetime(mut self, seconds: u64) -> Self {
        self.max_lifetime_in_seconds = seconds;
        self
    }
}

/// Seconds since the Unix epoch.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ============================================================================
// Token type
// ============================================================================

/// Opaque session token delivered to the client (wraps a `SessionId`).
#[derive(Clone, Debug)]
pub struct SessionToken(pub SessionId);

/// When a session login began: how often the user's sessions had been revoked.
#[derive(Debug, Clone, Copy)]
pub struct SessionTicket {
    revocations: u64,
}

// ============================================================================
// Session token strategy
// ============================================================================

fn build_session_cookie(value: &str, name: &str, ttl_seconds: u64) -> String {
    format!(
        "{}={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
        name, value, ttl_seconds
    )
}

/// Stateful session tokens: `issue` creates a server-side session, `revoke`
/// deletes it, validation is a store lookup (with sliding expiry).
#[derive(Clone)]
pub struct SessionTokens<S> {
    store: S,
    /// Shared with the validator; cloning the strategy copies a pointer.
    config: Arc<SessionConfig>,
    validator: SessionValidator<S>,
}

impl<S> SessionTokens<S>
where
    S: SessionStore + Clone,
{
    /// # Panics
    ///
    /// If `config.max_lifetime_in_seconds` is 0: no session could be used.
    pub fn new(store: S, config: SessionConfig) -> Self {
        assert!(
            config.max_lifetime_in_seconds > 0,
            "SessionConfig::max_lifetime_in_seconds must be greater than 0"
        );
        let config = Arc::new(config);
        let validator = SessionValidator::from_shared(store.clone(), config.clone());
        Self {
            store,
            config,
            validator,
        }
    }
}

#[async_trait]
impl<S> TokenStrategy for SessionTokens<S>
where
    S: SessionStore + Clone + Send + Sync + 'static,
{
    type Token = SessionToken;
    type Validator = SessionValidator<S>;
    type Error = SessionError;
    type Ticket = SessionTicket;

    async fn begin(&self, email: &Email) -> Result<SessionTicket, SessionError> {
        if self.store.is_user_locked(email).await? {
            return Err(SessionError::Locked);
        }
        Ok(SessionTicket {
            revocations: self.store.revocation_count(email).await?,
        })
    }

    async fn issue(
        &self,
        email: &Email,
        ticket: SessionTicket,
    ) -> Result<SessionToken, SessionError> {
        let id = SessionId::new();
        let record = SessionRecord {
            email: email.clone(),
            created_at: unix_now(),
        };
        self.store.create_session(id.clone(), record).await?;

        // Create first, then look: "delete all" counts before it deletes, so
        // either the count has moved by now (and the session goes here), or
        // the deletion comes after this session exists and removes it.
        if self.store.revocation_count(email).await? != ticket.revocations {
            match self.store.delete_session(&id).await {
                Ok(()) | Err(SessionStoreError::SessionNotFound) => {}
                Err(e) => return Err(e.into()),
            }
            return Err(SessionError::Superseded);
        }
        Ok(SessionToken(id))
    }

    async fn revoke(&self, token: &SessionToken) -> Result<(), SessionError> {
        self.store.delete_session(&token.0).await?;
        Ok(())
    }

    async fn revoke_all_for_user(&self, email: &Email) -> Result<(), SessionError> {
        // Sessions live server-side, so global revocation is just deleting them.
        self.store.delete_all_for_user(email).await?;
        Ok(())
    }

    async fn lock_user(&self, email: &Email) -> Result<Option<UserLock>, SessionError> {
        let lock = UserLock::new();
        let taken = self
            .store
            .try_lock_user(email, lock.holder(), USER_LOCK_TTL_SECONDS)
            .await?;
        Ok(taken.then_some(lock))
    }

    async fn unlock_user(&self, email: &Email, lock: UserLock) -> Result<(), SessionError> {
        Ok(self.store.unlock_user(email, lock.holder()).await?)
    }

    fn validator(&self) -> &SessionValidator<S> {
        &self.validator
    }

    fn cookie_name(&self) -> &str {
        &self.config.cookie_name
    }

    fn auth_cookie(&self, token: &SessionToken) -> String {
        // The browser may keep the cookie no longer than the session can live.
        build_session_cookie(
            &token.0.to_string(),
            &self.config.cookie_name,
            self.config
                .ttl_in_seconds
                .min(self.config.max_lifetime_in_seconds),
        )
    }

    fn extract<R: AuthRequest>(&self, req: &R) -> Option<SessionToken> {
        req.cookie(&self.config.cookie_name)
            .and_then(SessionId::parse)
            .map(SessionToken)
    }
}

// ============================================================================
// Scheme alias + session-specific constructors
// ============================================================================

/// Server-side session credential scheme: [`CredentialScheme`] with the session
/// token strategy. Slots match [`CredentialScheme`].
pub type SessionScheme<U, S, F = (), L = (), R = (), M = (), O = (), K = ()> =
    CredentialScheme<U, SessionTokens<S>, F, L, R, M, O, K>;

impl<U, S> CredentialScheme<U, SessionTokens<S>, (), (), (), (), (), ()>
where
    U: UserStore,
    S: SessionStore + Clone + Send + Sync + 'static,
{
    /// Create the session scheme: password login, logout, and session validation.
    ///
    /// Opt into optional capabilities with the `supports_*` methods.
    pub fn new(user_store: U, session_store: S, config: SessionConfig) -> Self {
        Self::from_tokens(user_store, SessionTokens::new(session_store, config))
    }
}

impl<U, S, F, R, M, O, K> CredentialScheme<U, SessionTokens<S>, F, (), R, M, O, K>
where
    S: SessionStore + Clone + Send + Sync + 'static,
{
    /// Enable elevated ("sudo") sessions from a separate store + config, lighting
    /// up [`SupportsElevation`](tempered_core::SupportsElevation).
    // The return type spells out every capability slot on purpose: it is the
    // typestate transition. An alias would hide which slot changes.
    #[allow(clippy::type_complexity)]
    pub fn supports_elevation<Cfg>(
        self,
        elevated_session_store: S,
        elevated_config: SessionConfig,
        configure: Cfg,
    ) -> CredentialScheme<U, SessionTokens<S>, F, Elevation<SessionTokens<S>>, R, M, O, K>
    where
        Cfg: FnOnce(ElevatedCapabilities) -> ElevatedCapabilities,
    {
        self.supports_elevation_with(
            SessionTokens::new(elevated_session_store, elevated_config),
            configure,
        )
    }
}

// ============================================================================
// Validator
// ============================================================================

/// Claims extracted from a valid session (currently just the user's email).
#[derive(Clone, Debug)]
pub struct SessionClaims {
    pub email: Email,
}

impl tempered_core::IdentityClaims for SessionClaims {
    fn subject(&self) -> &secrecy::Secret<String> {
        self.email.as_ref()
    }
}

#[derive(Clone)]
pub struct SessionValidator<S> {
    session_store: S,
    config: Arc<SessionConfig>,
}

impl<S> SessionValidator<S> {
    pub fn new(session_store: S, config: SessionConfig) -> Self {
        Self::from_shared(session_store, Arc::new(config))
    }

    pub(crate) fn from_shared(session_store: S, config: Arc<SessionConfig>) -> Self {
        Self {
            session_store,
            config,
        }
    }
}

#[async_trait]
impl<S> AuthValidator for SessionValidator<S>
where
    S: SessionStore + Clone + 'static,
{
    type Claims = SessionClaims;
    type RequestParts = http::request::Parts;
    type Error = SessionError;

    async fn validate(&self, parts: &Self::RequestParts) -> Result<Self::Claims, Self::Error> {
        let raw = cookie_value(parts, &self.config.cookie_name)
            .filter(|v| !v.is_empty())
            .ok_or(SessionError::MissingSession)?;

        let id = SessionId::parse(&raw).ok_or(SessionError::InvalidSession)?;

        // One store call: read the session and slide its idle timeout.
        let record = self.session_store.touch_session(&id).await?;

        // Past its absolute lifetime: gone, however recently it was used.
        // Deleting is tidying up (the age check alone already refuses it).
        if unix_now().saturating_sub(record.created_at) >= self.config.max_lifetime_in_seconds {
            let _ = self.session_store.delete_session(&id).await;
            return Err(SessionError::InvalidSession);
        }

        Ok(SessionClaims {
            email: record.email,
        })
    }
}

// ============================================================================
// Errors (shared by the strategy's issue/revoke and the validator)
// ============================================================================

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Missing session cookie")]
    MissingSession,
    #[error("Invalid session")]
    InvalidSession,
    #[error("Sessions were revoked while this login was in progress")]
    Superseded,
    #[error("The account is being updated")]
    Locked,
    #[error("Session store error: {0}")]
    Store(#[from] SessionStoreError),
}

impl ClassifyError for SessionError {
    fn classify(self) -> (ErrorCategory, String) {
        match self {
            SessionError::MissingSession => {
                (ErrorCategory::Unauthorized, "Missing session".to_string())
            }
            SessionError::InvalidSession => {
                (ErrorCategory::Unauthorized, "Invalid session".to_string())
            }
            SessionError::Superseded => (
                ErrorCategory::Unauthorized,
                "Sessions were revoked during login; log in again".to_string(),
            ),
            SessionError::Locked => (ErrorCategory::Conflict, ACCOUNT_BUSY.to_string()),
            SessionError::Store(SessionStoreError::SessionNotFound) => (
                ErrorCategory::Unauthorized,
                "Session not found or expired".to_string(),
            ),
            SessionError::Store(SessionStoreError::UnexpectedError(m)) => {
                tracing::error!(error = %m, "session store error");
                (ErrorCategory::Internal, "Internal error".to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionConfig, SessionError, SessionScheme};
    use crate::authentication::credential_scheme::{CredentialError, PasswordCredentials};
    use crate::persistence::hashmap_session_store::HashMapSessionStore;
    use crate::persistence::hashmap_user_store::HashMapUserStore;
    use secrecy::Secret;
    use tempered_core::{
        AuthValidator, AuthenticationScheme, Email, LoginOutcome, Password, SupportsElevation,
        User, UserStore,
    };

    fn config() -> SessionConfig {
        SessionConfig::new("session", 3600)
    }

    /// The scheme is cloned for every request; its config must be shared,
    /// not copied.
    #[test]
    fn a_clone_shares_the_config() {
        let tokens = super::SessionTokens::new(HashMapSessionStore::new(), config());
        let copy = tokens.clone();
        assert!(std::sync::Arc::ptr_eq(&tokens.config, &copy.config));
        assert!(std::sync::Arc::ptr_eq(
            &tokens.config,
            &copy.validator.config
        ));
    }

    #[tokio::test]
    async fn a_login_that_began_before_revoke_all_gets_no_session() {
        use super::SessionTokens;
        use crate::authentication::token_strategy::TokenStrategy;
        use tempered_core::SessionStore;

        let store = HashMapSessionStore::new();
        let tokens = SessionTokens::new(store.clone(), config());
        let email = Email::try_from(Secret::new("user@example.com".to_string())).unwrap();

        // The credential check happens between `begin` and `issue`. Here the
        // revocation lands in that gap: whatever was checked may be gone.
        let ticket = tokens.begin(&email).await.unwrap();
        tokens.revoke_all_for_user(&email).await.unwrap();
        let result = tokens.issue(&email, ticket).await;
        assert!(matches!(result, Err(SessionError::Superseded)));

        // A login that begins afterwards gets a session, and it is the only one.
        let ticket = tokens.begin(&email).await.unwrap();
        let token = tokens.issue(&email, ticket).await.unwrap();
        assert_eq!(store.get_session(&token.0).await.unwrap().email, email);
        tokens.revoke_all_for_user(&email).await.unwrap();
        assert!(store.get_session(&token.0).await.is_err());
    }

    #[tokio::test]
    async fn no_session_login_begins_while_the_user_is_locked() {
        use super::SessionTokens;
        use crate::authentication::token_strategy::TokenStrategy;

        let tokens = SessionTokens::new(HashMapSessionStore::new(), config());
        let email = Email::try_from(Secret::new("user@example.com".to_string())).unwrap();

        let lock = tokens.lock_user(&email).await.unwrap().expect("free");
        assert!(tokens.lock_user(&email).await.unwrap().is_none());
        assert!(matches!(
            tokens.begin(&email).await,
            Err(SessionError::Locked)
        ));

        tokens.unlock_user(&email, lock).await.unwrap();
        let ticket = tokens.begin(&email).await.unwrap();
        assert!(tokens.issue(&email, ticket).await.is_ok());
    }

    async fn scheme_with_user(
        email: &str,
        password: &str,
    ) -> SessionScheme<HashMapUserStore, HashMapSessionStore> {
        let user_store = HashMapUserStore::new();
        let user = User::parse(
            Secret::new(email.to_string()),
            Secret::new(password.to_string()),
            false,
        )
        .unwrap();
        user_store.add_user(user).await.unwrap();
        SessionScheme::new(user_store, HashMapSessionStore::new(), config())
    }

    fn credentials(email: &str, password: &str) -> PasswordCredentials {
        PasswordCredentials {
            email: Secret::new(email.to_string()),
            password: Secret::new(password.to_string()),
        }
    }

    fn parts_with_cookie(name: &str, value: &str) -> http::request::Parts {
        http::Request::builder()
            .header("cookie", format!("{}={}", name, value))
            .body(())
            .unwrap()
            .into_parts()
            .0
    }

    /// Sliding expiry keeps a busy session alive; the absolute lifetime
    /// ends it anyway, measured from when it was created.
    #[tokio::test]
    async fn a_session_past_its_maximum_lifetime_is_refused_and_removed() {
        use super::{SessionValidator, unix_now};
        use tempered_core::{SessionId, SessionRecord, SessionStore};

        let store = HashMapSessionStore::new();
        let validator = SessionValidator::new(
            store.clone(),
            SessionConfig::new("session", 3600).max_lifetime(600),
        );
        let email = Email::try_from(Secret::new("user@example.com".to_string())).unwrap();
        let session = |age: u64| {
            let id = SessionId::new();
            let record = SessionRecord {
                email: email.clone(),
                created_at: unix_now() - age,
            };
            let store = store.clone();
            async move {
                store.create_session(id.clone(), record).await.unwrap();
                id
            }
        };

        let young = session(599).await;
        let parts = parts_with_cookie("session", &young.to_string());
        assert!(validator.validate(&parts).await.is_ok());

        let old = session(600).await;
        let parts = parts_with_cookie("session", &old.to_string());
        assert!(matches!(
            validator.validate(&parts).await,
            Err(SessionError::InvalidSession)
        ));
        assert!(
            store.get_session(&old).await.is_err(),
            "removed from the store"
        );
    }

    #[test]
    fn the_default_lifetime_is_a_day_and_the_cookie_does_not_outlive_it() {
        use super::{DEFAULT_MAX_SESSION_LIFETIME_SECONDS, SessionTokens};
        use crate::authentication::token_strategy::TokenStrategy;

        assert_eq!(
            SessionConfig::new("s", 60).max_lifetime_in_seconds,
            DEFAULT_MAX_SESSION_LIFETIME_SECONDS
        );
        let tokens = SessionTokens::new(
            HashMapSessionStore::new(),
            SessionConfig::new("s", 7200).max_lifetime(600),
        );
        let cookie = tokens.auth_cookie(&super::SessionToken(tempered_core::SessionId::new()));
        assert!(cookie.ends_with("Max-Age=600"), "{cookie}");
    }

    #[tokio::test]
    async fn login_creates_session_and_validator_accepts_it() {
        let scheme = scheme_with_user("user@example.com", "passwordpassword").await;

        let outcome = scheme
            .login(credentials("user@example.com", "passwordpassword"))
            .await
            .unwrap();

        let token = match outcome {
            LoginOutcome::Success(t) => t,
            _ => panic!("expected immediate success"),
        };

        let parts = parts_with_cookie("session", &token.0.to_string());
        let claims = scheme.validator().validate(&parts).await.unwrap();
        assert_eq!(
            claims.email,
            Email::try_from(Secret::new("user@example.com".to_string())).unwrap()
        );
    }

    #[tokio::test]
    async fn logout_revokes_session_immediately() {
        let scheme = scheme_with_user("user@example.com", "passwordpassword").await;
        let outcome = scheme
            .login(credentials("user@example.com", "passwordpassword"))
            .await
            .unwrap();
        let token = match outcome {
            LoginOutcome::Success(t) => t,
            _ => panic!("expected success"),
        };

        scheme.logout(&token).await.unwrap();

        let parts = parts_with_cookie("session", &token.0.to_string());
        let result = scheme.validator().validate(&parts).await;
        assert!(result.is_err(), "revoked session must not validate");
    }

    #[tokio::test]
    async fn missing_cookie_is_rejected() {
        let scheme = scheme_with_user("user@example.com", "passwordpassword").await;
        let parts = http::Request::builder().body(()).unwrap().into_parts().0;
        let result = scheme.validator().validate(&parts).await;
        assert!(matches!(result, Err(SessionError::MissingSession)));
    }

    /// Behavior change from the old standalone scheme: a 2FA-flagged user logging
    /// into a session scheme that did not opt into 2FA now errors (consistent
    /// with JWT), instead of being granted a session immediately.
    #[tokio::test]
    async fn twofa_user_without_2fa_support_is_rejected() {
        let user_store = HashMapUserStore::new();
        let user = User::parse(
            Secret::new("user@example.com".to_string()),
            Secret::new("passwordpassword".to_string()),
            true, // requires 2FA
        )
        .unwrap();
        user_store.add_user(user).await.unwrap();
        let scheme = SessionScheme::new(user_store, HashMapSessionStore::new(), config());

        let result = scheme
            .login(credentials("user@example.com", "passwordpassword"))
            .await;
        assert!(matches!(result, Err(CredentialError::TwoFaNotConfigured)));
    }

    /// A capability the standalone session scheme never had: elevation. The
    /// elevated session is minted in a separate store and validates via the
    /// elevated validator.
    #[tokio::test]
    async fn inherited_elevation_issues_a_validatable_elevated_session() {
        let user_store = HashMapUserStore::new();
        let user = User::parse(
            Secret::new("user@example.com".to_string()),
            Secret::new("passwordpassword".to_string()),
            false,
        )
        .unwrap();
        user_store.add_user(user).await.unwrap();

        let scheme = SessionScheme::new(user_store, HashMapSessionStore::new(), config())
            .supports_elevation(
                HashMapSessionStore::new(),
                SessionConfig::new("elevated_session", 300),
                |e| e,
            );

        let email = Email::try_from(Secret::new("user@example.com".to_string())).unwrap();
        let password = Password::try_from(Secret::new("passwordpassword".to_string())).unwrap();
        let LoginOutcome::Success(elevated) = scheme.elevate(email, password).await.unwrap() else {
            panic!("no 2FA on this account");
        };

        let parts = parts_with_cookie("elevated_session", &elevated.0.to_string());
        let claims = scheme.elevated_validator().validate(&parts).await.unwrap();
        assert_eq!(
            claims.email,
            Email::try_from(Secret::new("user@example.com".to_string())).unwrap()
        );
    }

    /// An elevated session lives in its own store, so revoking the primary
    /// sessions does not reach it. Password change and account deletion must
    /// revoke it as well, or a stolen elevated session outlives a password
    /// reset and can set a password of its own.
    #[tokio::test]
    async fn revoking_a_user_also_revokes_their_elevated_sessions() {
        use tempered_core::{SupportsAccountDeletion, SupportsPasswordChange};

        let email = || Email::try_from(Secret::new("user@example.com".to_string())).unwrap();
        let password = || Password::try_from(Secret::new("passwordpassword".to_string())).unwrap();
        for revoke in ["change password", "delete account"] {
            let scheme = scheme_with_user("user@example.com", "passwordpassword")
                .await
                .supports_elevation(
                    HashMapSessionStore::new(),
                    SessionConfig::new("elevated_session", 300),
                    |e| e,
                );
            let LoginOutcome::Success(elevated) =
                scheme.elevate(email(), password()).await.unwrap()
            else {
                panic!("no 2FA on this account");
            };
            let parts = parts_with_cookie("elevated_session", &elevated.0.to_string());
            assert!(scheme.elevated_validator().validate(&parts).await.is_ok());

            match revoke {
                "change password" => {
                    let new = Password::try_from(Secret::new("another-password".to_string()));
                    scheme.change_password(email(), new.unwrap()).await.unwrap();
                }
                _ => scheme.delete_account(email()).await.unwrap(),
            }

            let result = scheme.elevated_validator().validate(&parts).await;
            assert!(result.is_err(), "{revoke} left the elevated session valid");
        }
    }
}
