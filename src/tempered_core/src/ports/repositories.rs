use async_trait::async_trait;
use secrecy::Secret;
use thiserror::Error;

use crate::domain::{
    api_key::ApiKeyId,
    email::Email,
    email_verification_token::EmailVerificationToken,
    passkey::{CeremonyId, CredentialId, PasskeyCredential, PendingCeremony},
    password::Password,
    password_reset_token::PasswordResetToken,
    session_id::SessionId,
    two_fa_attempt_id::TwoFaAttemptId,
    two_fa_code::TwoFaCode,
    user::{User, ValidatedUser},
};

// UserStore port trait and errors
#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Incorrect password")]
    IncorrectPassword,
    #[error("Unexpected error {0}")]
    UnexpectedError(String),
}

impl PartialEq for UserStoreError {
    /// Equal when the variants match; an `UnexpectedError` message is ignored.
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

#[async_trait]
pub trait UserStore: Send + Sync {
    async fn add_user(&self, user: User) -> Result<(), UserStoreError>;
    async fn set_new_password(
        &self,
        email: &Email,
        new_password: Password,
    ) -> Result<(), UserStoreError>;
    async fn authenticate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<ValidatedUser, UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    async fn delete_user(&self, user: &Email) -> Result<(), UserStoreError>;
}

// BannedTokenStore port trait and errors
#[derive(Debug, Error)]
pub enum BannedTokenStoreError {
    #[error("Database error: {0}")]
    DatabaseError(String),
}

#[async_trait]
pub trait BannedTokenStore: Send + Sync {
    async fn ban_token(&self, token: String) -> Result<(), BannedTokenStoreError>;
    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError>;
}

// TokenEpochStore port trait and errors
#[derive(Debug, Error)]
pub enum TokenEpochStoreError {
    #[error("Unexpected error: {0}")]
    UnexpectedError(String),
}

/// Per-user revocation cutoffs ("token epochs") for token schemes with no
/// server-side session registry (JWTs).
///
/// Global revocation for such schemes works by recording a per-user cutoff
/// instant: validation rejects any token whose issued-at (`iat`) is strictly
/// before the cutoff. `revoke_before(email, now)` therefore invalidates every
/// outstanding token for the user at once (password change, account deletion,
/// "log out everywhere").
///
/// Contract: a stored cutoff MUST remain readable for at least the longest
/// token TTL — if it expires earlier, a revoked (or deleted account's) token
/// becomes valid again for the rest of its lifetime.
#[async_trait]
pub trait TokenEpochStore: Send + Sync {
    /// Earliest issued-at (unix seconds) still valid for this user;
    /// `None` = no cutoff recorded.
    async fn min_valid_iat(&self, email: &Email) -> Result<Option<i64>, TokenEpochStoreError>;

    /// Invalidate every token issued *strictly before* `cutoff` (unix
    /// seconds). Implementations MUST keep the highest cutoff seen, never
    /// lower it.
    async fn revoke_before(&self, email: &Email, cutoff: i64) -> Result<(), TokenEpochStoreError>;
}

// TwoFaCodeStore port trait and errors
#[derive(Debug, Error)]
pub enum TwoFaCodeStoreError {
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid session")]
    InvalidAttemptId,
    #[error("Invalid 2FA code")]
    Invalid2FACode,
    #[error("Too many failed attempts")]
    TooManyAttempts,
    #[error("2FA code expired")]
    CodeExpired,
    #[error("Unexpected error")]
    UnexpectedError(String),
}

#[cfg(debug_assertions)]
impl PartialEq for TwoFaCodeStoreError {
    /// Equal when the variants match; an `UnexpectedError` message is ignored.
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

// PasswordResetTokenStore port trait and errors
//
// Maps token → email so complete_password_reset can recover the email from only the token.
#[derive(Debug, Error)]
pub enum PasswordResetTokenStoreError {
    #[error("Token not found")]
    TokenNotFound,
    #[error("Unexpected error: {0}")]
    UnexpectedError(String),
}

#[async_trait]
pub trait PasswordResetTokenStore: Send + Sync {
    async fn store_token(
        &self,
        token: PasswordResetToken,
        email: Email,
    ) -> Result<(), PasswordResetTokenStoreError>;

    async fn get_email_for_token(
        &self,
        token: &PasswordResetToken,
    ) -> Result<Email, PasswordResetTokenStoreError>;

    async fn delete_token(
        &self,
        token: &PasswordResetToken,
    ) -> Result<(), PasswordResetTokenStoreError>;

    /// Retrieve and remove the email for a token in one atomic step, so a
    /// reset token cannot be redeemed twice by concurrent requests. Mirrors
    /// [`EmailVerificationTokenStore::consume_token`].
    async fn consume_token(
        &self,
        token: &PasswordResetToken,
    ) -> Result<Email, PasswordResetTokenStoreError>;
}

// EmailVerificationTokenStore port trait and errors
#[derive(Debug, Error)]
pub enum EmailVerificationStoreError {
    #[error("Token not found or expired")]
    TokenNotFound,
    #[error("Unexpected error: {0}")]
    UnexpectedError(String),
}

/// Maps verification tokens to emails (pending verifications) and tracks verified status.
#[async_trait]
pub trait EmailVerificationTokenStore: Send + Sync {
    /// Store a pending verification token for the given email.
    async fn store_pending_verification(
        &self,
        token: EmailVerificationToken,
        email: Email,
    ) -> Result<(), EmailVerificationStoreError>;

    /// Retrieve and remove the email associated with a token.
    async fn consume_token(
        &self,
        token: &EmailVerificationToken,
    ) -> Result<Email, EmailVerificationStoreError>;

    /// Mark an email address as verified.
    async fn mark_verified(&self, email: &Email) -> Result<(), EmailVerificationStoreError>;

    /// Check whether the email address has been verified.
    async fn is_verified(&self, email: &Email) -> Result<bool, EmailVerificationStoreError>;
}

// Passkey (WebAuthn) ports and errors
#[derive(Debug, Error)]
pub enum PasskeyStoreError {
    #[error("Credential not found")]
    CredentialNotFound,
    #[error("Credential id is already registered")]
    CredentialAlreadyExists,
    #[error("Unexpected error: {0}")]
    UnexpectedError(String),
}

#[async_trait]
pub trait PasskeyCredentialStore: Send + Sync {
    /// Store a newly enrolled credential.
    ///
    /// Must fail with [`PasskeyStoreError::CredentialAlreadyExists`] if the
    /// credential id is already present, for any owner. Overwriting would hand
    /// an existing credential — and the account it logs in to — to a new owner.
    async fn add_credential(&self, cred: PasskeyCredential) -> Result<(), PasskeyStoreError>;
    async fn get_credential(
        &self,
        id: &CredentialId,
    ) -> Result<PasskeyCredential, PasskeyStoreError>;
    async fn list_for_user(
        &self,
        owner: &Email,
    ) -> Result<Vec<PasskeyCredential>, PasskeyStoreError>;

    /// Record a successful authentication: set the signature counter and, when
    /// `credential_data` is `Some`, replace the stored opaque credential data.
    async fn update_after_authentication(
        &self,
        id: &CredentialId,
        new_sign_count: u32,
        credential_data: Option<Vec<u8>>,
    ) -> Result<(), PasskeyStoreError>;
}

#[derive(Debug, Error)]
pub enum ChallengeStoreError {
    #[error("Challenge not found or expired")]
    ChallengeNotFound,
    #[error("Unexpected error: {0}")]
    UnexpectedError(String),
}

/// Holds in-flight WebAuthn ceremonies between their `start` and `finish` legs:
/// the verifier's opaque challenge state and the user the ceremony is for.
///
/// Entries are single-use and should expire after a short TTL (minutes). The
/// state is server-side only; the client only ever sees the [`CeremonyId`].
#[async_trait]
pub trait ChallengeStore: Send + Sync {
    async fn store_ceremony(
        &self,
        id: CeremonyId,
        ceremony: PendingCeremony,
    ) -> Result<(), ChallengeStoreError>;

    /// Consume a ceremony. Succeeds at most once per stored id: a second call
    /// (a replayed `finish`) must fail with
    /// [`ChallengeStoreError::ChallengeNotFound`].
    async fn consume_ceremony(
        &self,
        id: &CeremonyId,
    ) -> Result<PendingCeremony, ChallengeStoreError>;
}

// OAuth ports and errors
#[derive(Debug, Error)]
pub enum OAuthStateStoreError {
    #[error("Unknown or expired state")]
    UnknownState,
    #[error("Unexpected error: {0}")]
    UnexpectedError(String),
}

/// Stores the single-use anti-CSRF `state` value, together with the PKCE
/// `code_verifier` generated for the same authorization request, between the
/// authorize redirect and the callback.
///
/// The verifier is a secret: it never leaves the server except in the
/// back-channel token request. Production implementations should apply a short
/// TTL (minutes) and consume atomically.
#[async_trait]
pub trait OAuthStateStore: Send + Sync {
    /// Persist a pending `state` and the PKCE verifier bound to it.
    async fn store_state(
        &self,
        state: String,
        code_verifier: Secret<String>,
    ) -> Result<(), OAuthStateStoreError>;

    /// Consume a `state` value, returning the PKCE verifier stored with it.
    ///
    /// Succeeds at most once per stored state: a second call (a replayed
    /// callback) must fail with [`OAuthStateStoreError::UnknownState`].
    async fn consume_state(&self, state: &str) -> Result<Secret<String>, OAuthStateStoreError>;
}

#[derive(Debug, Error)]
pub enum OAuthIdentityStoreError {
    #[error("Identity already linked to a different account")]
    AlreadyLinked,
    #[error("Unexpected error: {0}")]
    UnexpectedError(String),
}

/// Maps an external provider identity `(provider, subject)` to a local user email.
#[async_trait]
pub trait OAuthIdentityStore: Send + Sync {
    /// Link a provider identity to a local email.
    ///
    /// Idempotent when the identity already maps to the *same* email, but must
    /// fail with [`OAuthIdentityStoreError::AlreadyLinked`] if `(provider,
    /// subject)` is already bound to a *different* email — silently moving the
    /// binding would enable account takeover. Re-linking to a different account
    /// must be a deliberate, re-authenticated action.
    async fn link_identity(
        &self,
        provider: String,
        subject: String,
        email: Email,
    ) -> Result<(), OAuthIdentityStoreError>;

    /// Find the local email previously linked to a provider identity.
    async fn find_email(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<Email>, OAuthIdentityStoreError>;
}

// ApiKeyStore port, records and errors
//
// Keys are stored as a SHA-256 hash of the secret half only — the plaintext is
// shown to the caller exactly once at creation and never persisted.
#[derive(Debug, Clone)]
pub struct ApiKeyRecord {
    pub id: ApiKeyId,
    /// Non-secret lookup handle (the part before the `.`).
    pub prefix: String,
    /// Hex SHA-256 of the secret half.
    pub secret_hash: String,
    pub owner: Email,
    pub scopes: Vec<String>,
}

/// Non-secret metadata returned when listing a user's keys.
#[derive(Debug, Clone)]
pub struct ApiKeyMetadata {
    pub id: ApiKeyId,
    pub prefix: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Error)]
pub enum ApiKeyStoreError {
    #[error("API key not found")]
    NotFound,
    #[error("Unexpected error: {0}")]
    UnexpectedError(String),
}

#[async_trait]
pub trait ApiKeyStore: Send + Sync {
    /// Persist a newly-issued key record.
    async fn create_key(&self, record: ApiKeyRecord) -> Result<(), ApiKeyStoreError>;

    /// Look up a key record by its non-secret prefix.
    async fn find_by_prefix(&self, prefix: &str) -> Result<ApiKeyRecord, ApiKeyStoreError>;

    /// Revoke (delete) a key by id.
    async fn revoke_key(&self, id: &ApiKeyId) -> Result<(), ApiKeyStoreError>;

    /// List non-secret metadata for all of a user's keys.
    async fn list_for_user(&self, owner: &Email) -> Result<Vec<ApiKeyMetadata>, ApiKeyStoreError>;
}

// SessionStore port trait and errors
//
// Backs the opaque server-side session scheme: maps a random SessionId to the
// authenticated user's email. Deleting an entry instantly revokes the session.
#[derive(Debug, Error)]
pub enum SessionStoreError {
    #[error("Session not found")]
    SessionNotFound,
    #[error("Unexpected error: {0}")]
    UnexpectedError(String),
}

#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Create a new session for the given user.
    async fn create_session(&self, id: SessionId, email: Email) -> Result<(), SessionStoreError>;

    /// Look up the user associated with a session id.
    async fn get_session(&self, id: &SessionId) -> Result<Email, SessionStoreError>;

    /// Refresh a session's expiry (sliding-window). In-memory stores may no-op.
    async fn touch_session(&self, id: &SessionId) -> Result<(), SessionStoreError>;

    /// Delete a single session (logout).
    async fn delete_session(&self, id: &SessionId) -> Result<(), SessionStoreError>;

    /// Delete every session belonging to a user (logout-everywhere / password change).
    async fn delete_all_for_user(&self, email: &Email) -> Result<(), SessionStoreError>;
}

#[async_trait]
pub trait TwoFaCodeStore: Send + Sync {
    async fn store_code(
        &self,
        user_id: Email,
        login_attempt_id: TwoFaAttemptId,
        two_fa_code: TwoFaCode,
    ) -> Result<(), TwoFaCodeStoreError>;

    /// Check a presented code against the stored one.
    ///
    /// Contract: implementations MUST bound the guessing budget — count failed
    /// attempts and, past a cap, delete the code and return
    /// [`TwoFaCodeStoreError::TooManyAttempts`]; stored codes MUST expire
    /// (return [`TwoFaCodeStoreError::CodeExpired`] past their TTL). A 6-digit
    /// code is brute-forceable within its lifetime without both.
    async fn validate(
        &self,
        user_id: &Email,
        login_attempt_id: &TwoFaAttemptId,
        two_fa_code: &TwoFaCode,
    ) -> Result<(), TwoFaCodeStoreError>;

    async fn get_login_attempt_id_and_two_fa_code(
        &self,
        user_id: &Email,
    ) -> Result<(TwoFaAttemptId, TwoFaCode), TwoFaCodeStoreError>;

    async fn delete(&self, user_id: &Email) -> Result<(), TwoFaCodeStoreError>;
}
