//! Axum-specific elevation route.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use secrecy::Secret;
use serde::Deserialize;
use tempered_adapters::handlers;
use tempered_core::{Email, HttpElevationScheme, Password, SupportsElevation};
use thiserror::Error;

use crate::adapters::response_builder;

/// Axum elevation route.
///
/// This route is Axum-specific - it uses Axum's extractors and error handling.
/// The actual elevation logic is in the framework-agnostic handler.
#[tracing::instrument(name = "Elevate privileges", skip(scheme, request))]
pub async fn elevate<S>(
    State(scheme): State<S>,
    Json(request): Json<ElevateRequest>,
) -> Result<impl IntoResponse, ElevateError>
where
    S: HttpElevationScheme + SupportsElevation,
{
    // Parse domain entities
    let email =
        Email::try_from(request.email).map_err(|e| ElevateError::InvalidEmail(e.to_string()))?;
    let password = Password::try_from(request.password)
        .map_err(|e| ElevateError::InvalidPassword(e.to_string()))?;

    let builder = response_builder();

    handlers::handle_elevate(&scheme, email, password, builder)
        .await
        .map_err(ElevateError::Failed)
}

/// Axum-specific request body for elevation
#[derive(Debug, Deserialize)]
pub struct ElevateRequest {
    /// User's email address
    pub email: Secret<String>,

    /// User's password for re-authentication
    pub password: Secret<String>,
}

/// Errors that can occur during elevation
#[derive(Debug, Error)]
pub enum ElevateError {
    #[error("Invalid email: {0}")]
    InvalidEmail(String),

    #[error("Invalid password: {0}")]
    InvalidPassword(String),

    #[error("Elevation failed: {0}")]
    Failed(String),
}

impl IntoResponse for ElevateError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            ElevateError::InvalidEmail(msg) => (StatusCode::BAD_REQUEST, msg),
            ElevateError::InvalidPassword(msg) => (StatusCode::BAD_REQUEST, msg),
            ElevateError::Failed(msg) => (StatusCode::UNAUTHORIZED, msg),
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}
