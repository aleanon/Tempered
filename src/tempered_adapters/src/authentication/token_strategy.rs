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
    pub fn new(config: JwtAuthConfig, banned: B, epoch: impl TokenEpochStore + 'static) -> Self {
        Self::from_parts(config, banned, Arc::new(epoch))
    }

    pub(crate) fn from_parts(
        config: JwtAuthConfig,
        banned: B,
        epoch: Arc<dyn TokenEpochStore>,
    ) -> Self {
        let validator = LocalJwtValidator::new(banned.clone(), config.clone(), epoch.clone());
        Self {
            config,
            banned,
            epoch,
            validator,
        }
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
}

impl ClassifyError for JwtTokenError {
    fn classify(self) -> (ErrorCategory, String) {
        match self {
            // Preserve the previous mapping: a token (signing/decoding) error uses
            // its own status; a ban-store failure is a 500.
            JwtTokenError::Generate(e) => e.classify(),
            JwtTokenError::Revoke(e) => {
                (ErrorCategory::Internal, format!("Token store error: {}", e))
            }
            JwtTokenError::RevokeAll(e) => {
                tracing::error!(error = %e, "failed to record revocation cutoff");
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
