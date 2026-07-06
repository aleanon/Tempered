use async_trait::async_trait;
use thiserror::Error;

use crate::domain::{
    api_key::ApiKeyId,
    email::Email,
    email_verification_token::EmailVerificationToken,
    passkey::{CredentialId, PasskeyCredential, WebAuthnChallenge},
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
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::UserAlreadyExists, Self::UserAlreadyExists) => true,
            (Self::UserNotFound, Self::UserNotFound) => true,
            (Self::IncorrectPassword, Self::IncorrectPassword) => true,
            (Self::UnexpectedError(_), Self::UnexpectedError(_)) => true,
            _ => false,
        }
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

// TwoFaCodeStore port trait and errors
#[derive(Debug, Error)]
pub enum TwoFaCodeStoreError {
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid session")]
    InvalidAttemptId,
    #[error("Invalid 2FA code")]
    Invalid2FACode,
    #[error("Unexpected error")]
    UnexpectedError(String),
}

#[cfg(debug_assertions)]
impl PartialEq for TwoFaCodeStoreError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::UserNotFound, Self::UserNotFound) => true,
            (Self::InvalidAttemptId, Self::InvalidAttemptId) => true,
            (Self::Invalid2FACode, Self::Invalid2FACode) => true,
            (Self::UnexpectedError(_), Self::UnexpectedError(_)) => true,
            _ => false,
        }
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
    #[error("Unexpected error: {0}")]
    UnexpectedError(String),
}

#[async_trait]
pub trait PasskeyCredentialStore: Send + Sync {
    async fn add_credential(&self, cred: PasskeyCredential) -> Result<(), PasskeyStoreError>;
    async fn get_credential(
        &self,
        id: &CredentialId,
    ) -> Result<PasskeyCredential, PasskeyStoreError>;
    async fn list_for_user(
        &self,
        owner: &Email,
    ) -> Result<Vec<PasskeyCredential>, PasskeyStoreError>;
    async fn update_sign_count(
        &self,
        id: &CredentialId,
        new_count: u32,
    ) -> Result<(), PasskeyStoreError>;
}

#[derive(Debug, Error)]
pub enum ChallengeStoreError {
    #[error("Challenge not found or expired")]
    ChallengeNotFound,
    #[error("Unexpected error: {0}")]
    UnexpectedError(String),
}

/// Stores single-use WebAuthn challenges. A registration challenge is bound to
/// the enrolling user's email; a usernameless authentication challenge carries
/// `None`.
#[async_trait]
pub trait ChallengeStore: Send + Sync {
    async fn store_challenge(
        &self,
        challenge: WebAuthnChallenge,
        email: Option<Email>,
    ) -> Result<(), ChallengeStoreError>;

    /// Consume a challenge, returning the email it was bound to (if any).
    async fn consume_challenge(
        &self,
        challenge: &WebAuthnChallenge,
    ) -> Result<Option<Email>, ChallengeStoreError>;
}

// OAuth ports and errors
#[derive(Debug, Error)]
pub enum OAuthStateStoreError {
    #[error("Unknown or expired state")]
    UnknownState,
    #[error("Unexpected error: {0}")]
    UnexpectedError(String),
}

/// Stores the single-use anti-CSRF `state` value between the authorize redirect
/// and the callback. (A production implementation should also bind the PKCE
/// verifier here and apply a short TTL.)
#[async_trait]
pub trait OAuthStateStore: Send + Sync {
    async fn store_state(&self, state: String) -> Result<(), OAuthStateStoreError>;

    /// Consume a `state` value, succeeding only if it was previously stored.
    async fn consume_state(&self, state: &str) -> Result<(), OAuthStateStoreError>;
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
    async fn create_session(&self, id: SessionId, email: Email)
    -> Result<(), SessionStoreError>;

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
