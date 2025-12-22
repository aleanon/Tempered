//! Axum-specific elevated token verification route.

use axum::body::Body;
use axum::http::Request;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use tempered_adapters::handlers;
use tempered_core::HttpElevationScheme;
use thiserror::Error;

use crate::adapters::{AxumRequest, response_builder};

/// Axum elevated token verification route.
///
/// This route is Axum-specific - it uses Axum's extractors and error handling.
/// The actual verification logic is in the framework-agnostic handler.
#[tracing::instrument(name = "Verify Elevated Token", skip(scheme, headers))]
pub async fn verify_elevated_token<S>(
    State(scheme): State<S>,
    headers: HeaderMap,
) -> axum::response::Response
where
    S: HttpElevationScheme + Clone + Send + Sync + 'static,
{
    // Create a minimal request from headers for cookie extraction
    let req = Request::builder().body(Body::empty()).unwrap();

    let (mut parts, body) = req.into_parts();
    parts.headers = headers;
    let request = Request::from_parts(parts, body);

    let builder = response_builder();
    let axum_req = AxumRequest(request);

    match handlers::handle_verify_elevated_token(&scheme, &axum_req, builder).await {
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
