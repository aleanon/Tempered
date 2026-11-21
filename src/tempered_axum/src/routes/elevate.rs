//! Axum-specific elevation route.

use axum::{Extension, Json, extract::State, http::StatusCode, response::IntoResponse};
use secrecy::{ExposeSecret, Secret};
use serde::Deserialize;
use tempered_adapters::{handlers, http::HttpResponseBuilder};
use tempered_core::{
    AuthValidator, ClassifyError, Email, HttpElevationScheme, IdentityClaims, Password,
    constant_time_eq,
};
use thiserror::Error;

use crate::adapters::into_axum_response;
use crate::error::status_code;

/// Axum elevation route.
///
/// This route is Axum-specific - it uses Axum's extractors and error handling.
/// The actual elevation logic is in the framework-agnostic handler.
///
/// This route sits behind the login-validation middleware, which inserts the
/// scheme's validated claims into the request extensions. They are read through
/// [`IdentityClaims`], so the route works for any token strategy (JWT, session). Elevation is bound to that
/// session: the body's credentials must belong to the logged-in user, otherwise
/// knowing another user's password would yield an elevated token for *them*.
#[tracing::instrument(name = "Elevate privileges", skip(scheme, claims, request))]
pub async fn elevate<S>(
    State(scheme): State<S>,
    Extension(claims): Extension<<S::Validator as AuthValidator>::Claims>,
    Json(request): Json<ElevateRequest>,
) -> Result<impl IntoResponse, ElevateError>
where
    S: HttpElevationScheme,
    S::ElevationError: ClassifyError,
    <S::Validator as AuthValidator>::Claims: IdentityClaims,
{
    // Parse domain entities
    let email =
        Email::try_from(request.email).map_err(|e| ElevateError::InvalidEmail(e.to_string()))?;
    let password = Password::try_from(request.password)
        .map_err(|e| ElevateError::InvalidPassword(e.to_string()))?;

    // The body email is attacker-controlled and the session subject is secret,
    // so compare in constant time.
    if !constant_time_eq(
        claims.subject().expose_secret(),
        email.as_ref().expose_secret(),
    ) {
        return Err(ElevateError::NotSessionOwner);
    }

    let builder = HttpResponseBuilder::new();

    let http_response = handlers::handle_elevate(&scheme, email, password, builder)
        .await
        .map_err(|(category, message)| ElevateError::Failed(status_code(category), message))?;

    Ok(into_axum_response(http_response))
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

    #[error("Elevation failed: {1}")]
    Failed(StatusCode, String),

    #[error("Elevation must target the logged-in user")]
    NotSessionOwner,
}

impl IntoResponse for ElevateError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            ElevateError::InvalidEmail(msg) => (StatusCode::BAD_REQUEST, msg),
            ElevateError::InvalidPassword(msg) => (StatusCode::BAD_REQUEST, msg),
            ElevateError::Failed(status, msg) => (status, msg),
            ElevateError::NotSessionOwner => (
                StatusCode::FORBIDDEN,
                "Elevation must target the logged-in user".to_string(),
            ),
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}
