//! Axum-specific token verification route.

use axum::{Json, http::StatusCode, response::IntoResponse};
use tempered_adapters::{handlers, http::HttpResponseBuilder};
use tempered_core::HttpAuthenticationScheme;
use thiserror::Error;

use crate::adapters::into_axum_response;

/// Axum token verification route.
///
/// This route assumes the token has already been validated by middleware.
/// It simply returns a success response.
#[tracing::instrument(name = "Verify Token")]
pub async fn verify_token<S>() -> impl IntoResponse
where
    S: HttpAuthenticationScheme + Clone + Send + Sync + 'static,
{
    let builder = HttpResponseBuilder::new();

    match handlers::handle_verify_token(builder).await {
        Ok(http_response) => into_axum_response(http_response).into_response(),
        Err(e) => VerifyTokenError::Failed(e).into_response(),
    }
}

/// Errors that can occur during token verification
#[derive(Debug, Error)]
pub enum VerifyTokenError {
    #[error("Token verification failed: {0}")]
    Failed(String),
}

impl IntoResponse for VerifyTokenError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            VerifyTokenError::Failed(msg) => (StatusCode::UNAUTHORIZED, msg),
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}
