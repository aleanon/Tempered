use thiserror::Error;

#[derive(Debug, Error)]
pub enum TwoFaError {
    #[error("Invalid login attempt ID")]
    InvalidLoginAttemptID,
    #[error("Invalid two-factor code")]
    InvalidTwoFaCode,
}
