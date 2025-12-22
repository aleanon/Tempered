// pub mod jwt;
pub mod local_jwt_validator;

use axum::response::{IntoResponse, Response};
// pub use jwt::{
//     Claims, TokenAuthError, create_auth_cookie, create_removal_cookie, extract_token,
//     generate_auth_cookie, generate_elevated_auth_cookie, validate_auth_token,
//     validate_elevated_auth_token,
// };
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
