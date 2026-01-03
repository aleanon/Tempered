//! Axum-specific elevated token verification route.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use tempered_adapters::handlers;
use tempered_core::HttpElevationScheme;
use thiserror::Error;

use crate::adapters::{AuthRequestExtractor, response_builder};

/// Axum elevated token verification route.
///
/// This route is Axum-specific - it uses Axum's extractors and error handling.
/// The actual verification logic is in the framework-agnostic handler.
#[tracing::instrument(name = "Verify Elevated Token", skip(scheme, req))]
pub async fn verify_elevated_token<S>(
    State(scheme): State<S>,
    req: AuthRequestExtractor,
) -> impl IntoResponse
where
    S: HttpElevationScheme + Clone + Send + Sync + 'static,
{
    let builder = response_builder();

    match handlers::handle_verify_elevated_token(&scheme, &req, builder).await {
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
