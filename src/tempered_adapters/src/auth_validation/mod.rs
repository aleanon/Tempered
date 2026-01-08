pub mod local_jwt_validator;

use axum::response::{IntoResponse, Response};
use reqwest::StatusCode;

#[derive(Debug)]
pub enum AuthenticationError {
    MissingAuthenticator,
    AuthenticationFailed(String),
}

impl IntoResponse for AuthenticationError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthenticationError::MissingAuthenticator => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Authentication not configured".to_string(),
            ),
            AuthenticationError::AuthenticationFailed(msg) => {
                (StatusCode::UNAUTHORIZED, msg.to_string())
            }
        };

        (status, message).into_response()
    }
}
