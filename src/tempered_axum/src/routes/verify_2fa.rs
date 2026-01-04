//! Axum-specific 2FA verification route.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use secrecy::{ExposeSecret, Secret};
use serde::Deserialize;
use tempered_adapters::handlers::{
    self,
    verify_2fa::{Verify2FaData, Verify2FaError},
};
use tempered_core::{HttpAuthenticationScheme, IntoStatusMessage, SupportsTwoFactor};

use crate::adapters::response_builder;

/// Axum 2FA verification route.
///
/// This route is Axum-specific - it uses Axum's extractors and error handling.
/// The actual 2FA verification logic is in the framework-agnostic handler.
#[tracing::instrument(name = "Verify 2FA", skip(scheme, request))]
pub async fn verify_2fa<S>(
    State(scheme): State<S>,
    Json(request): Json<Verify2FaRequest>,
) -> impl IntoResponse
where
    S: HttpAuthenticationScheme + SupportsTwoFactor,
    S::TwoFactorError: IntoStatusMessage,
{
    // Convert Axum request to framework-agnostic data
    let data = Verify2FaData {
        email: request.email.expose_secret().clone(),
        login_attempt_id: request.login_attempt_id,
        two_factor_code: request.two_factor_code,
    };

    let builder = response_builder();

    match handlers::handle_verify_2fa(&scheme, data, builder).await {
        Ok(response) => response.into_response(),
        Err(e) => {
            let (status, message) = match e {
                Verify2FaError::InvalidEmail(err) => (StatusCode::BAD_REQUEST, err.to_string()),
                Verify2FaError::InvalidAttemptId(err) => (StatusCode::BAD_REQUEST, err.to_string()),
                Verify2FaError::InvalidCode(err) => (StatusCode::BAD_REQUEST, err.to_string()),
                Verify2FaError::VerificationFailed(err) => err.into_status_message(),
            };
            (status, Json(serde_json::json!({ "error": message }))).into_response()
        }
    }
}

/// Axum-specific request body for 2FA verification
#[derive(Debug, Deserialize)]
pub struct Verify2FaRequest {
    /// User's email address
    pub email: Secret<String>,

    /// Login attempt ID from the initial login response
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,

    /// The 2FA code (TOTP, SMS code, etc.)
    #[serde(rename = "2FACode")]
    pub two_factor_code: String,
}
