use auth_application::{
    ChangePasswordError, DeleteAccountError, ElevateError, LoginError, LogoutError, Verify2FaError,
};
use auth_core::{
    BannedTokenStoreError, TwoFaCodeStoreError, TwoFaError, UserError, UserStoreError,
};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::auth::TokenAuthError;

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Debug, Error)]
pub enum AuthApiError {
    #[error("User not found")]
    UserNotFound,

    #[error("User already exists")]
    UserAlreadyExists,

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Missing token")]
    MissingToken,

    #[error("Authentication failed: {0}")]
    AuthenticationError(String),

    #[error("Invalid login attempt ID")]
    InvalidLoginAttemptId,

    #[error("Invalid two-factor authentication code")]
    InvalidTwoFaCode,

    #[error("Unexpected error: {0}")]
    UnexpectedError(String),
}

impl IntoResponse for AuthApiError {
    fn into_response(self) -> Response {
        let (status_code, error_message) = match self {
            AuthApiError::InvalidInput(_) | AuthApiError::MissingToken => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }

            AuthApiError::UserAlreadyExists => (StatusCode::CONFLICT, self.to_string()),

            AuthApiError::AuthenticationError(_)
            | AuthApiError::UserNotFound
            | AuthApiError::InvalidLoginAttemptId
            | AuthApiError::InvalidTwoFaCode => (StatusCode::UNAUTHORIZED, self.to_string()),

            AuthApiError::UnexpectedError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
        };

        let body = Json(ErrorResponse {
            error: error_message,
        });

        (status_code, body).into_response()
    }
}

impl From<UserError> for AuthApiError {
    fn from(error: UserError) -> Self {
        AuthApiError::InvalidInput(error.to_string())
    }
}

impl From<UserStoreError> for AuthApiError {
    fn from(error: UserStoreError) -> Self {
        match error {
            UserStoreError::UserAlreadyExists => AuthApiError::UserAlreadyExists,
            UserStoreError::UserNotFound => AuthApiError::UserNotFound,
            UserStoreError::IncorrectPassword => {
                AuthApiError::AuthenticationError(error.to_string())
            }
            UserStoreError::UnexpectedError(e) => AuthApiError::UnexpectedError(e),
        }
    }
}

impl From<TokenAuthError> for AuthApiError {
    fn from(error: TokenAuthError) -> Self {
        match error {
            TokenAuthError::InvalidToken
            | TokenAuthError::TokenError(_)
            | TokenAuthError::TokenIsBanned => AuthApiError::AuthenticationError(error.to_string()),
            TokenAuthError::MissingToken => AuthApiError::MissingToken,
            TokenAuthError::UnexpectedError(e) => AuthApiError::UnexpectedError(e.to_string()),
        }
    }
}

impl From<BannedTokenStoreError> for AuthApiError {
    fn from(error: BannedTokenStoreError) -> Self {
        AuthApiError::UnexpectedError(error.to_string())
    }
}

impl From<TwoFaCodeStoreError> for AuthApiError {
    fn from(error: TwoFaCodeStoreError) -> Self {
        match error {
            TwoFaCodeStoreError::UserNotFound => AuthApiError::UserNotFound,
            TwoFaCodeStoreError::InvalidAttemptId | TwoFaCodeStoreError::Invalid2FACode => {
                AuthApiError::AuthenticationError(error.to_string())
            }
            TwoFaCodeStoreError::UnexpectedError(e) => AuthApiError::UnexpectedError(e),
        }
    }
}

impl From<TwoFaError> for AuthApiError {
    fn from(error: TwoFaError) -> Self {
        AuthApiError::InvalidInput(error.to_string())
    }
}

impl From<LoginError> for AuthApiError {
    fn from(error: LoginError) -> Self {
        match error {
            LoginError::UserStoreError(e) => e.into(),
            LoginError::TwoFaCodeStoreError(e) => e.into(),
            LoginError::EmailError(e) => AuthApiError::UnexpectedError(e),
        }
    }
}

impl From<LogoutError> for AuthApiError {
    fn from(error: LogoutError) -> Self {
        match error {
            LogoutError::BannedTokenStoreError(e) => e.into(),
        }
    }
}

impl From<Verify2FaError> for AuthApiError {
    fn from(error: Verify2FaError) -> Self {
        match error {
            Verify2FaError::TwoFaCodeStoreError(e) => e.into(),
            Verify2FaError::TwoFaError(e) => e.into(),
            Verify2FaError::InvalidLoginAttemptId => AuthApiError::InvalidLoginAttemptId,
            Verify2FaError::InvalidTwoFaCode => AuthApiError::InvalidTwoFaCode,
        }
    }
}

impl From<ElevateError> for AuthApiError {
    fn from(error: ElevateError) -> Self {
        match error {
            ElevateError::UserStoreError(e) => e.into(),
        }
    }
}

impl From<ChangePasswordError> for AuthApiError {
    fn from(error: ChangePasswordError) -> Self {
        match error {
            ChangePasswordError::UserStoreError(e) => e.into(),
        }
    }
}

impl From<DeleteAccountError> for AuthApiError {
    fn from(error: DeleteAccountError) -> Self {
        match error {
            DeleteAccountError::UserStoreError(e) => e.into(),
        }
    }
}
