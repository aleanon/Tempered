//! The token mechanism, factored out of the credential scheme.
//!
//! `JwtScheme` and `SessionScheme` are the *same* scheme — authenticate
//! credentials, then issue / validate / revoke a token in a cookie — differing
//! only in how the token is represented (a signed JWT vs a server-side session
//! id). [`TokenStrategy`] is exactly that seam: everything else
//! ([`CredentialScheme`](crate::authentication::credential_scheme::CredentialScheme)
//! and its capabilities) is written once, generic over the strategy.

use std::sync::Arc;

use async_trait::async_trait;
use secrecy::ExposeSecret;
use tempered_core::{
    AuthRequest, AuthValidator, BannedTokenStore, BannedTokenStoreError, ClassifyError, Email,
    ErrorCategory, TokenEpochStore,
};
use thiserror::Error;

use crate::auth_validation::local_jwt_validator::{
    JwtAuthConfig, LocalJwtValidator, TokenAuthError, create_auth_cookie,
    generate_auth_token_issued_at,
};

/// How a credential scheme mints, validates, and revokes its session token.
///
/// The bound is required only where a concrete strategy is *constructed*; the
/// generic credential scheme calls these methods without ever naming JWT or
/// session details.
#[async_trait]
pub trait TokenStrategy: Clone + Send + Sync + 'static {
    /// The token handed to the client (and read back on later requests).
    type Token: Clone + Send + Sync + 'static;
    /// The validator the middleware runs on protected routes.
    type Validator: AuthValidator<RequestParts = http::request::Parts>;
    /// Errors from issuing/revoking (validation errors belong to the validator).
    type Error: std::error::Error + Send + Sync + 'static + ClassifyError;

    /// Proof of when a login began, taken by [`begin`](Self::begin) and spent
    /// by [`issue`](Self::issue).
    type Ticket: Send + Sync + 'static;

    /// Open a login for `email`. Call this **before** checking the credential
    /// (password, 2FA code, passkey, provider link) that the login rests on.
    ///
    /// The ticket pins the login to the user's revocation state at this
    /// moment. If [`revoke_all_for_user`](Self::revoke_all_for_user) runs
    /// before the token is issued, the credential that was checked may no
    /// longer exist, and the token must not survive.
    async fn begin(&self, email: &Email) -> Result<Self::Ticket, Self::Error>;

    /// Mint a token for an identity whose credential was checked after
    /// `ticket` was taken.
    ///
    /// Contract: if `revoke_all_for_user` ran for this user since the ticket
    /// was taken, the result MUST NOT be a usable token: either this returns
    /// an error, or the token it returns fails validation.
    async fn issue(&self, email: &Email, ticket: Self::Ticket) -> Result<Self::Token, Self::Error>;

    /// Invalidate a token (logout / ban / delete).
    async fn revoke(&self, token: &Self::Token) -> Result<(), Self::Error>;

    /// Invalidate every outstanding token/session for a user (password
    /// change, account deletion, "log out everywhere").
    ///
    /// Contract: after this returns `Ok`, tokens issued to this user *before*
    /// the call MUST fail validation. This is deliberately a required method
    /// with no default — global revocation is correctness-critical, so a
    /// strategy that cannot support it must say so explicitly in its own
    /// impl, visibly against this contract.
    async fn revoke_all_for_user(&self, email: &Email) -> Result<(), Self::Error>;

    /// Take the user's credential lock, or `None` if someone else holds it.
    ///
    /// Held while the user's credentials are removed (account deletion,
    /// securing an unproven account) and while a new credential is stored
    /// (passkey enrolment), so the two cannot interleave: a session that is
    /// about to be revoked cannot leave a fresh credential behind.
    ///
    /// Contract: the take is atomic; while the lock is held
    /// [`begin`](Self::begin) fails for this user; the lock expires on its own
    /// after [`USER_LOCK_TTL_SECONDS`], so a holder that crashed cannot lock
    /// the user out.
    async fn lock_user(&self, email: &Email) -> Result<Option<UserLock>, Self::Error>;

    /// Release a lock taken with [`lock_user`](Self::lock_user). Releasing a
    /// lock that has expired (and may be held by someone else) does nothing.
    async fn unlock_user(&self, email: &Email, lock: UserLock) -> Result<(), Self::Error>;

    /// The validator middleware uses.
    fn validator(&self) -> &Self::Validator;

    /// The cookie this token lives in.
    fn cookie_name(&self) -> &str;

    /// Build the full `Set-Cookie` value delivering `token` (the format — TTL,
    /// flags — is the strategy's concern).
    fn auth_cookie(&self, token: &Self::Token) -> String;

    /// Pull the token back out of a request.
    fn extract<R: AuthRequest>(&self, req: &R) -> Option<Self::Token>;
}

/// How long a credential lock lives if its holder never releases it. The work
/// done under it is a handful of store calls.
pub const USER_LOCK_TTL_SECONDS: u64 = 10;

/// Proof of holding a user's credential lock: the random name it was taken
/// under, which only the holder knows.
#[derive(Debug)]
pub struct UserLock {
    holder: String,
}

impl UserLock {
    /// A lock under a fresh random holder name.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            holder: uuid::Uuid::new_v4().to_string(),
        }
    }

    pub fn holder(&self) -> &str {
        &self.holder
    }
}

// ============================================================================
// JWT token type
// ============================================================================

/// A signed JWT delivered to / read from the client.
#[derive(Debug, Clone)]
pub struct JwtToken(pub String);

impl JwtToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<String> for JwtToken {
    fn from(s: String) -> Self {
        JwtToken(s)
    }
}

// ============================================================================
// JWT strategy
// ============================================================================

/// The shortest JWT secret [`JwtTokens`] accepts, in bytes (256 bits, the
/// HS256 output size).
pub const MIN_JWT_SECRET_BYTES: usize = 32;

/// JWT tokens: `issue` signs, `revoke` bans one token, validation is local
/// signature checking plus the ban-list and revocation-cutoff lookups.
#[derive(Clone)]
pub struct JwtTokens<B> {
    config: JwtAuthConfig,
    banned: B,
    epoch: Arc<dyn TokenEpochStore>,
    validator: LocalJwtValidator<B>,
}

impl<B> JwtTokens<B>
where
    B: BannedTokenStore + Clone,
{
    /// The epoch store is required infrastructure, like the ban store: it is
    /// what makes `revoke_all_for_user` (password change, account deletion)
    /// actually invalidate outstanding tokens. Use `HashMapTokenEpochStore`
    /// in development and `RedisTokenEpochStore` (TTL ≥ the token TTL) in
    /// production.
    ///
    /// # Panics
    ///
    /// If the secret is shorter than [`MIN_JWT_SECRET_BYTES`]. HS256 with a
    /// short secret can be brute-forced offline from a single token; this is
    /// a configuration error, caught at startup. Generate one with
    /// `openssl rand -base64 48`.
    pub fn new(config: JwtAuthConfig, banned: B, epoch: impl TokenEpochStore + 'static) -> Self {
        Self::from_parts(config, banned, Arc::new(epoch))
    }

    pub(crate) fn from_parts(
        config: JwtAuthConfig,
        banned: B,
        epoch: Arc<dyn TokenEpochStore>,
    ) -> Self {
        let length = config.jwt_secret.expose_secret().len();
        assert!(
            length >= MIN_JWT_SECRET_BYTES,
            "the JWT secret for cookie {:?} is {length} bytes; use at least {MIN_JWT_SECRET_BYTES} random bytes",
            config.jwt_cookie_name,
        );
        let validator = LocalJwtValidator::new(banned.clone(), config.clone(), epoch.clone());
        Self {
            config,
            banned,
            epoch,
            validator,
        }
    }

    /// Whether `other` signs with the same secret as this strategy.
    pub(crate) fn shares_secret_with(&self, other: &JwtAuthConfig) -> bool {
        tempered_core::constant_time_eq(
            self.config.jwt_secret.expose_secret(),
            other.jwt_secret.expose_secret(),
        )
    }

    /// The revocation-cutoff store, shared so companion strategies (e.g. the
    /// elevated-token strategy) revoke together with the primary one.
    pub fn epoch(&self) -> Arc<dyn TokenEpochStore> {
        self.epoch.clone()
    }
}

#[async_trait]
impl<B> TokenStrategy for JwtTokens<B>
where
    B: BannedTokenStore + Clone + Send + Sync + 'static,
{
    type Token = JwtToken;
    type Validator = LocalJwtValidator<B>;
    type Error = JwtTokenError;
    type Ticket = JwtTicket;

    async fn begin(&self, email: &Email) -> Result<JwtTicket, JwtTokenError> {
        if self
            .epoch
            .is_user_locked(email)
            .await
            .map_err(JwtTokenError::Cutoff)?
        {
            return Err(JwtTokenError::Locked);
        }
        // The stamp the token will carry: now, or the user's revocation cutoff
        // if that is ahead of the clock (right after a "revoke all" the cutoff
        // is one second ahead, see below). An unreadable cutoff fails the
        // login rather than guessing.
        let cutoff = self
            .epoch
            .min_valid_iat(email)
            .await
            .map_err(JwtTokenError::Cutoff)?;
        let now = chrono::Utc::now().timestamp();
        Ok(JwtTicket {
            issued_at: cutoff.map_or(now, |cutoff| cutoff.max(now)),
        })
    }

    async fn issue(&self, email: &Email, ticket: JwtTicket) -> Result<JwtToken, JwtTokenError> {
        // Stamped with the moment the login began, not the moment it finished.
        // A "revoke all" in between moved the cutoff past this stamp, so the
        // validator rejects the token: no check is needed here.
        let token = generate_auth_token_issued_at(email, &self.config, ticket.issued_at)
            .map_err(JwtTokenError::Generate)?;
        Ok(JwtToken(token))
    }

    async fn revoke(&self, token: &JwtToken) -> Result<(), JwtTokenError> {
        self.banned
            .ban_token(token.0.clone())
            .await
            .map_err(JwtTokenError::Revoke)?;
        Ok(())
    }

    async fn revoke_all_for_user(&self, email: &Email) -> Result<(), JwtTokenError> {
        // Move the user's cutoff one second past the latest stamp any of their
        // tokens can carry. That is "now", or an earlier cutoff that is still
        // ahead of the clock (a second revocation within the same second,
        // whose in-between login was stamped at that cutoff). The validator
        // rejects every token with an earlier iat (see LocalJwtValidator), and
        // `begin` stamps the next login at the new cutoff, so it is valid at
        // once.
        let latest_stamp = self
            .epoch
            .min_valid_iat(email)
            .await
            .map_err(JwtTokenError::Cutoff)?
            .map_or(chrono::Utc::now().timestamp(), |cutoff| {
                cutoff.max(chrono::Utc::now().timestamp())
            });
        self.epoch
            .revoke_before(email, latest_stamp + 1)
            .await
            .map_err(JwtTokenError::RevokeAll)?;
        Ok(())
    }

    async fn lock_user(&self, email: &Email) -> Result<Option<UserLock>, JwtTokenError> {
        let lock = UserLock::new();
        let taken = self
            .epoch
            .try_lock_user(email, lock.holder(), USER_LOCK_TTL_SECONDS)
            .await
            .map_err(JwtTokenError::Lock)?;
        Ok(taken.then_some(lock))
    }

    async fn unlock_user(&self, email: &Email, lock: UserLock) -> Result<(), JwtTokenError> {
        self.epoch
            .unlock_user(email, lock.holder())
            .await
            .map_err(JwtTokenError::Lock)
    }

    fn validator(&self) -> &LocalJwtValidator<B> {
        &self.validator
    }

    fn cookie_name(&self) -> &str {
        &self.config.jwt_cookie_name
    }

    fn auth_cookie(&self, token: &JwtToken) -> String {
        let max_age = time::Duration::seconds(self.config.token_ttl_in_seconds as i64);
        create_auth_cookie(token.0.clone(), &self.config.jwt_cookie_name, Some(max_age)).to_string()
    }

    fn extract<R: AuthRequest>(&self, req: &R) -> Option<JwtToken> {
        req.cookie(&self.config.jwt_cookie_name)
            .map(|s| JwtToken(s.to_string()))
    }
}

/// What a client is told when a login or enrolment meets a held credential lock.
pub(crate) const ACCOUNT_BUSY: &str = "The account is being updated; try again in a moment";

/// When a JWT login began: the issued-at stamp its token will carry.
#[derive(Debug, Clone, Copy)]
pub struct JwtTicket {
    issued_at: i64,
}

/// Errors from the JWT strategy's issue/revoke steps.
#[derive(Debug, Error)]
pub enum JwtTokenError {
    #[error("Token error: {0}")]
    Generate(TokenAuthError),
    #[error("Failed to ban JWT token: {0}")]
    Revoke(BannedTokenStoreError),
    #[error("Failed to record revocation cutoff: {0}")]
    RevokeAll(tempered_core::TokenEpochStoreError),
    #[error("Failed to read revocation cutoff: {0}")]
    Cutoff(tempered_core::TokenEpochStoreError),
    #[error("The account is being updated")]
    Locked,
    #[error("Failed to take or release the credential lock: {0}")]
    Lock(tempered_core::TokenEpochStoreError),
}

impl ClassifyError for JwtTokenError {
    fn classify(self) -> (ErrorCategory, String) {
        match self {
            // Preserve the previous mapping: a token (signing/decoding) error uses
            // its own status; a ban-store failure is a 500.
            JwtTokenError::Generate(e) => e.classify(),
            JwtTokenError::Revoke(e) => {
                tracing::error!(error = %e, "banned token store error");
                (ErrorCategory::Internal, "Internal error".to_string())
            }
            JwtTokenError::RevokeAll(e) => {
                tracing::error!(error = %e, "failed to record revocation cutoff");
                (ErrorCategory::Internal, "Internal error".to_string())
            }
            JwtTokenError::Locked => (ErrorCategory::Conflict, ACCOUNT_BUSY.to_string()),
            JwtTokenError::Lock(e) => {
                tracing::error!(error = %e, "credential lock store error");
                (ErrorCategory::Internal, "Internal error".to_string())
            }
            JwtTokenError::Cutoff(e) => {
                tracing::error!(error = %e, "failed to read revocation cutoff");
                (ErrorCategory::Internal, "Internal error".to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use secrecy::Secret;

    use crate::persistence::{HashMapTokenEpochStore, HashSetBannedTokenStore};

    use super::*;

    fn email() -> Email {
        Email::try_from(Secret::new("test@example.com".to_string())).unwrap()
    }

    fn strategy() -> JwtTokens<HashSetBannedTokenStore> {
        JwtTokens::new(
            JwtAuthConfig {
                jwt_cookie_name: "jwt".to_string(),
                jwt_secret: Secret::new("a-test-secret-that-is-long-enough".to_string()),
                token_ttl_in_seconds: 3600,
                audience: None,
                issuer: None,
            },
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
    }

    #[test]
    #[should_panic(expected = "use at least 32 random bytes")]
    fn a_short_jwt_secret_is_refused_at_startup() {
        let config = JwtAuthConfig {
            jwt_cookie_name: "jwt".to_string(),
            jwt_secret: Secret::new("secret".to_string()),
            token_ttl_in_seconds: 3600,
            audience: None,
            issuer: None,
        };
        JwtTokens::new(
            config,
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        );
    }

    #[tokio::test]
    async fn revoke_all_records_a_cutoff_the_validator_reads() {
        let tokens = strategy();
        assert_eq!(tokens.epoch().min_valid_iat(&email()).await.unwrap(), None);

        let before = chrono::Utc::now().timestamp();
        tokens.revoke_all_for_user(&email()).await.unwrap();

        let cutoff = tokens
            .epoch()
            .min_valid_iat(&email())
            .await
            .unwrap()
            .expect("revoke_all_for_user must record a cutoff");
        assert!(cutoff > before);
    }

    #[tokio::test]
    async fn revoke_all_rejects_a_token_issued_a_moment_earlier_and_accepts_the_next_one() {
        let tokens = strategy();

        // No second boundary is crossed between these three steps (unless the
        // clock happens to tick): this is the case whole-second cutoffs used
        // to miss.
        let earlier = login(&tokens).await;
        tokens.revoke_all_for_user(&email()).await.unwrap();
        let next = login(&tokens).await;

        assert!(!validates(&tokens, &earlier).await);
        assert!(validates(&tokens, &next).await);

        // Revoking again rejects that one too.
        tokens.revoke_all_for_user(&email()).await.unwrap();
        assert!(!validates(&tokens, &next).await);
    }

    #[tokio::test]
    async fn a_stamp_ahead_of_the_clock_does_not_lengthen_the_token() {
        use crate::auth_validation::local_jwt_validator::validate_auth_token;

        let tokens = strategy();
        // Several revocations within a second push the cutoff, and so the
        // next token's stamp, ahead of the clock.
        for _ in 0..5 {
            tokens.revoke_all_for_user(&email()).await.unwrap();
        }
        let now = chrono::Utc::now().timestamp();
        let token = login(&tokens).await;

        let claims = validate_auth_token(
            token.as_str(),
            &tokens.banned,
            tokens.epoch.as_ref(),
            &tokens.config,
        )
        .await
        .unwrap();
        assert!(claims.iat.unwrap() > now);
        let ttl = tokens.config.token_ttl_in_seconds as usize;
        assert!(claims.exp <= now as usize + ttl + 1);
    }

    #[tokio::test]
    async fn a_login_that_began_before_revoke_all_does_not_yield_a_valid_token() {
        let tokens = strategy();

        // The credential check happens between `begin` and `issue`. Here the
        // revocation lands in that gap: whatever was checked may be gone.
        let ticket = tokens.begin(&email()).await.unwrap();
        tokens.revoke_all_for_user(&email()).await.unwrap();
        let token = tokens.issue(&email(), ticket).await.unwrap();
        assert!(!validates(&tokens, &token).await);

        // A login that begins afterwards is unaffected.
        assert!(validates(&tokens, &login(&tokens).await).await);
    }

    #[tokio::test]
    async fn no_login_begins_while_the_user_is_locked() {
        let tokens = strategy();

        let lock = tokens.lock_user(&email()).await.unwrap().expect("free");
        assert!(tokens.lock_user(&email()).await.unwrap().is_none());
        assert!(matches!(
            tokens.begin(&email()).await,
            Err(JwtTokenError::Locked)
        ));

        tokens.unlock_user(&email(), lock).await.unwrap();
        assert!(validates(&tokens, &login(&tokens).await).await);
    }

    /// A whole login with nothing in between.
    async fn login(tokens: &JwtTokens<HashSetBannedTokenStore>) -> JwtToken {
        let ticket = tokens.begin(&email()).await.unwrap();
        tokens.issue(&email(), ticket).await.unwrap()
    }

    async fn validates(tokens: &JwtTokens<HashSetBannedTokenStore>, token: &JwtToken) -> bool {
        use tempered_core::AuthValidator;

        let parts = http::Request::builder()
            .header("cookie", format!("jwt={}", token.as_str()))
            .body(())
            .unwrap()
            .into_parts()
            .0;
        tokens.validator().validate(&parts).await.is_ok()
    }
}
