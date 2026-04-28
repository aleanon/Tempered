use async_trait::async_trait;
use thiserror::Error;

use crate::domain::{
    email::Email,
    email_verification_token::EmailVerificationToken,
    password::Password,
    password_reset_token::PasswordResetToken,
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
