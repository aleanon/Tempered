//! Axum-specific logout route.

use axum::body::Body;
use axum::http::Request;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use tempered_adapters::handlers;
use tempered_core::{HttpAuthenticationScheme, SupportsTokenRevocation};
use thiserror::Error;

use crate::adapters::{AxumRequest, response_builder};

/// Axum logout route.
///
/// This route is Axum-specific - it uses Axum's extractors and error handling.
/// The actual logout logic is in the framework-agnostic handler.
#[tracing::instrument(name = "Logout", skip(scheme, headers))]
pub async fn logout<S>(State(scheme): State<S>, headers: HeaderMap) -> axum::response::Response
where
    S: HttpAuthenticationScheme + SupportsTokenRevocation + Clone + Send + Sync + 'static,
{
    // Create a minimal request from headers for cookie extraction
    let req = Request::builder()
        .extension(headers.clone())
        .body(Body::empty())
        .unwrap();

    // Manually add headers to the request
    let (mut parts, body) = req.into_parts();
    parts.headers = headers;
    let req = Request::from_parts(parts, body);

    let builder = response_builder();
    let axum_req = AxumRequest(req);

    match handlers::handle_logout(&scheme, &axum_req, builder).await {
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
