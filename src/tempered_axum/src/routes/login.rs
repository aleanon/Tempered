//! Axum-specific login route.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use tempered_adapters::handlers;
use tempered_core::HttpAuthenticationScheme;
use thiserror::Error;

use crate::adapters::response_builder;

/// Axum login route.
///
/// This route is Axum-specific - it uses Axum's extractors and error handling.
/// The actual authentication logic is in the framework-agnostic handler.
#[tracing::instrument(name = "Login", skip(scheme, credentials))]
pub async fn login<S>(
    State(scheme): State<S>,
    Json(credentials): Json<S::Credentials>,
) -> Result<impl IntoResponse, LoginError>
where
    S: HttpAuthenticationScheme,
{
    let builder = response_builder();

    handlers::handle_login(&scheme, credentials, builder)
        .await
        .map_err(LoginError::AuthenticationFailed)
}

/// Errors that can occur during login
#[derive(Debug, Error)]
pub enum LoginError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
}

impl IntoResponse for LoginError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            LoginError::AuthenticationFailed(msg) => (StatusCode::UNAUTHORIZED, msg),
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}
