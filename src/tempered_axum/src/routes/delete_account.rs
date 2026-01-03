//! Axum-specific account deletion route.
//!
//! This route requires elevated authentication - users must re-authenticate before deleting their account.

use axum::{Extension, Json, extract::State, http::StatusCode, response::IntoResponse};
use tempered_adapters::auth_validation::local_jwt_validator::Claims;
use tempered_core::{Email, HttpAuthenticationScheme, SupportsAccountDeletion};
use thiserror::Error;

/// Axum account deletion route.
///
/// This route is Axum-specific - it uses Axum's extractors and error handling.
/// The actual account deletion logic is in the framework-agnostic handler.
///
/// Note: This route expects an elevated token to be verified by middleware,
/// with the claims extracted and provided via Extension.
#[tracing::instrument(name = "Delete Account", skip(scheme, claims))]
pub async fn delete_account<S>(
    State(scheme): State<S>,
    Extension(claims): Extension<Claims>,
) -> Result<impl IntoResponse, DeleteAccountError>
where
    S: HttpAuthenticationScheme + SupportsAccountDeletion + Clone + 'static,
{
    // Extract email from claims
    let email =
        Email::try_from(claims.sub).map_err(|e| DeleteAccountError::InvalidEmail(e.to_string()))?;

    scheme
        .delete_account(email)
        .await
        .map_err(|e| DeleteAccountError::Failed(e.to_string()))?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "success",
            "message": "Account deleted successfully"
        })),
    ))
}

/// Errors that can occur during account deletion
#[derive(Debug, Error)]
pub enum DeleteAccountError {
    #[error("Invalid email: {0}")]
    InvalidEmail(String),

    #[error("Account deletion failed: {0}")]
    Failed(String),
}

impl IntoResponse for DeleteAccountError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            DeleteAccountError::InvalidEmail(msg) => (StatusCode::BAD_REQUEST, msg),
            DeleteAccountError::Failed(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}
