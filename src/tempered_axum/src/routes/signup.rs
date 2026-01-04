//! Axum-specific signup route.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use secrecy::Secret;
use serde::Deserialize;
use tempered_adapters::handlers::{self, signup::SignupData};
use tempered_core::{Email, IntoStatusMessage, Password, SupportsRegistration};

use crate::adapters::response_builder;

/// Axum signup route.
///
/// This route is Axum-specific - it uses Axum's extractors and error handling.
/// The actual signup logic is in the framework-agnostic handler.
#[tracing::instrument(name = "Signup", skip(scheme, request))]
pub async fn signup<S>(
    State(scheme): State<S>,
    Json(request): Json<SignupRequest<S::RegistrationData>>,
) -> impl IntoResponse
where
    S: SupportsRegistration,
    S::RegistrationError: IntoStatusMessage,
{
    // Parse domain entities
    let email = match Email::try_from(request.email) {
        Ok(email) => email,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    let password = match Password::try_from(request.password) {
        Ok(password) => password,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    // Create signup data
    let data = SignupData {
        email,
        password,
        registration_data: request.registration_data,
    };

    let builder = response_builder();

    match handlers::handle_signup(&scheme, data, builder).await {
        Ok(response) => response.into_response(),
        Err(e) => {
            let (status, message) = e.into_status_message();
            (status, Json(serde_json::json!({ "error": message }))).into_response()
        }
    }
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
