//! Axum-specific elevated token verification route.

use axum::{Json, http::StatusCode, response::IntoResponse};
use tempered_adapters::handlers;
use tempered_core::HttpElevationScheme;
use thiserror::Error;

use crate::adapters::response_builder;

/// Axum elevated token verification route.
///
/// This route assumes the elevated token has already been validated by middleware.
/// It simply returns a success response.
#[tracing::instrument(name = "Verify Elevated Token")]
pub async fn verify_elevated_token<S>() -> impl IntoResponse
where
    S: HttpElevationScheme + Clone + Send + Sync + 'static,
{
    let builder = response_builder();

    match handlers::handle_verify_elevated_token(builder).await {
        Ok(resp) => resp.into_response(),
        Err(e) => VerifyElevatedTokenError::Failed(e).into_response(),
    }
}

/// Errors that can occur during elevated token verification
#[derive(Debug, Error)]
pub enum VerifyElevatedTokenError {
    #[error("Elevated token verification failed: {0}")]
    Failed(String),
}

impl IntoResponse for VerifyElevatedTokenError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            VerifyElevatedTokenError::Failed(msg) => (StatusCode::UNAUTHORIZED, msg),
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}
