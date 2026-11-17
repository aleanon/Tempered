//! Axum-specific account deletion route.
//!
//! This route requires elevated authentication - users must re-authenticate before deleting their account.

use axum::{Extension, Json, extract::State, http::StatusCode, response::IntoResponse};
use tempered_core::{Email, HttpAuthenticationScheme, IdentityClaims, SupportsAccountDeletion};
use thiserror::Error;

/// Axum account deletion route.
///
/// This route is Axum-specific - it uses Axum's extractors and error handling.
/// The actual account deletion logic is in the framework-agnostic handler.
///
/// The route sits behind the login or the elevated middleware, depending on how
/// the scheme was configured. `C` is the claims type that middleware inserts;
/// the user is read through [`IdentityClaims`], so the route works for any
/// token strategy (JWT, session) at either level.
#[tracing::instrument(name = "Delete Account", skip(scheme, claims))]
pub async fn delete_account<S, C>(
    State(scheme): State<S>,
    Extension(claims): Extension<C>,
) -> Result<impl IntoResponse, DeleteAccountError>
where
    S: HttpAuthenticationScheme + SupportsAccountDeletion + Clone + 'static,
    C: IdentityClaims + Clone + Send + Sync + 'static,
{
    // The user is whoever the validated token belongs to.
    let email = Email::try_from(claims.subject().clone())
        .map_err(|e| DeleteAccountError::InvalidEmail(e.to_string()))?;

    scheme
        .delete_account(email)
        .await
        .map_err(|e| DeleteAccountError::Failed(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
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
