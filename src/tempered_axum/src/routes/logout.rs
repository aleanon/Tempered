//! Axum-specific logout route.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use tempered_adapters::handlers;
use tempered_core::{HttpAuthenticationScheme, SupportsTokenRevocation};
use thiserror::Error;

use crate::adapters::{AuthRequestExtractor, response_builder};

/// Axum logout route.
///
/// This route is Axum-specific - it uses Axum's extractors and error handling.
/// The actual logout logic is in the framework-agnostic handler.
#[tracing::instrument(name = "Logout", skip(scheme, req))]
pub async fn logout<S>(State(scheme): State<S>, req: AuthRequestExtractor) -> impl IntoResponse
where
    S: HttpAuthenticationScheme + SupportsTokenRevocation + Clone + Send + Sync + 'static,
{
    let builder = response_builder();

    match handlers::handle_logout(&scheme, &req, builder).await {
        Ok(resp) => resp.into_response(),
        Err(e) => LogoutError::Failed(e).into_response(),
    }
}

/// Errors that can occur during logout
#[derive(Debug, Error)]
pub enum LogoutError {
    #[error("Logout failed: {0}")]
    Failed(String),
}

impl IntoResponse for LogoutError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            LogoutError::Failed(msg) => (StatusCode::UNAUTHORIZED, msg),
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}
