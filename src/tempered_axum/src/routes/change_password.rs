//! Axum-specific password change route.
//!
//! This route requires elevated authentication - users must re-authenticate before changing their password.

use crate::IntoStatusMessage;
use axum::{Extension, Json, extract::State, http::StatusCode, response::IntoResponse};
use secrecy::Secret;
use serde::Deserialize;
use tempered_core::{
    Email, HttpAuthenticationScheme, IdentityClaims, Password, SupportsPasswordChange,
};
use thiserror::Error;

/// Axum password change route.
///
/// This route is Axum-specific - it uses Axum's extractors and error handling.
/// The actual password change logic is in the framework-agnostic handler.
///
/// The route sits behind the login or the elevated middleware, depending on how
/// the scheme was configured. `C` is the claims type that middleware inserts;
/// the user is read through [`IdentityClaims`], so the route works for any
/// token strategy (JWT, session) at either level.
#[tracing::instrument(name = "Change Password", skip(scheme, claims, request))]
pub async fn change_password<S, C>(
    State(scheme): State<S>,
    Extension(claims): Extension<C>,
    Json(request): Json<ChangePasswordRequest>,
) -> Result<impl IntoResponse, ChangePasswordError>
where
    S: HttpAuthenticationScheme + SupportsPasswordChange + Send + 'static + Clone,
    S::PasswordChangeError: IntoStatusMessage,
    C: IdentityClaims + Clone + Send + Sync + 'static,
{
    // The user is whoever the validated token belongs to.
    let email = Email::try_from(claims.subject().clone())
        .map_err(|e| ChangePasswordError::InvalidEmail(e.to_string()))?;

    // Parse new password
    let new_password = Password::try_from(request.new_password)
        .map_err(|e| ChangePasswordError::InvalidPassword(e.to_string()))?;

    scheme
        .change_password(email, new_password)
        .await
        .map_err(|e| {
            let (status, message) = e.into_status_message();
            ChangePasswordError::Failed(status, message)
        })?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "success",
            "message": "Password changed successfully"
        })),
    ))
}

/// Axum-specific request body for password change
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    /// New password
    pub new_password: Secret<String>,
}

/// Errors that can occur during password change
#[derive(Debug, Error)]
pub enum ChangePasswordError {
    #[error("Invalid email: {0}")]
    InvalidEmail(String),

    #[error("Invalid password: {0}")]
    InvalidPassword(String),

    #[error("Password change failed: {1}")]
    Failed(StatusCode, String),
}

impl IntoResponse for ChangePasswordError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            ChangePasswordError::InvalidEmail(msg) => (StatusCode::BAD_REQUEST, msg),
            ChangePasswordError::InvalidPassword(msg) => (StatusCode::BAD_REQUEST, msg),
            ChangePasswordError::Failed(status, msg) => (status, msg),
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}
