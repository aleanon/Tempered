//! Axum-specific token verification route.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use tempered_adapters::handlers;
use tempered_core::HttpAuthenticationScheme;
use thiserror::Error;

use crate::adapters::{AuthRequestExtractor, response_builder};

/// Axum token verification route.
///
/// This route is Axum-specific - it uses Axum's extractors and error handling.
/// The actual verification logic is in the framework-agnostic handler.
#[tracing::instrument(name = "Verify Token", skip(scheme, req))]
pub async fn verify_token<S>(
    State(scheme): State<S>,
    req: AuthRequestExtractor,
) -> impl IntoResponse
where
    S: HttpAuthenticationScheme + Clone + Send + Sync + 'static,
{
    let builder = response_builder();

    match handlers::handle_verify_token(&scheme, &req, builder).await {
        Ok(resp) => resp.into_response(),
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
