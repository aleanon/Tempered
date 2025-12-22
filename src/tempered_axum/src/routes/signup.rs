//! Axum-specific signup route.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use secrecy::Secret;
use serde::Deserialize;
use tempered_adapters::handlers::{self, signup::SignupData};
use tempered_core::{Email, Password, SupportsRegistration};
use thiserror::Error;

use crate::adapters::response_builder;

/// Axum signup route.
///
/// This route is Axum-specific - it uses Axum's extractors and error handling.
/// The actual signup logic is in the framework-agnostic handler.
#[tracing::instrument(name = "Signup", skip(scheme, request))]
pub async fn signup<S>(
    State(scheme): State<S>,
    Json(request): Json<SignupRequest<S::RegistrationData>>,
) -> Result<impl IntoResponse, SignupError>
where
    S: SupportsRegistration,
{
    // Parse domain entities
    let email =
        Email::try_from(request.email).map_err(|e| SignupError::InvalidEmail(e.to_string()))?;
    let password = Password::try_from(request.password)
        .map_err(|e| SignupError::InvalidPassword(e.to_string()))?;

    // Create signup data
    let data = SignupData {
        email,
        password,
        registration_data: request.registration_data,
    };

    let builder = response_builder();

    handlers::handle_signup(&scheme, data, builder)
        .await
        .map_err(SignupError::RegistrationFailed)
}

/// Axum-specific request body for signup
#[derive(Debug, Deserialize)]
pub struct SignupRequest<D> {
    /// User's email address
    pub email: Secret<String>,

    /// User's password
    pub password: Secret<String>,

    /// Additional registration data (scheme-specific)
    #[serde(flatten)]
    pub registration_data: D,
}

/// Errors that can occur during signup
#[derive(Debug, Error)]
pub enum SignupError {
    #[error("Invalid email: {0}")]
    InvalidEmail(String),

    #[error("Invalid password: {0}")]
    InvalidPassword(String),

    #[error("Registration failed: {0}")]
    RegistrationFailed(String),
}

impl IntoResponse for SignupError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            SignupError::InvalidEmail(msg) => (StatusCode::BAD_REQUEST, msg),
            SignupError::InvalidPassword(msg) => (StatusCode::BAD_REQUEST, msg),
            SignupError::RegistrationFailed(msg) => (StatusCode::BAD_REQUEST, msg),
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}
