//! Ask for another email-verification link, for the logged-in user.

use axum::{Extension, Json, extract::State, http::StatusCode, response::IntoResponse};
use tempered_core::{Email, IdentityClaims, RequiresEmailVerification};

use crate::IntoStatusMessage;

/// Sends a new verification link to the logged-in user's address (nothing if
/// it is already verified). Login-gated, not verified-gated: it is how an
/// unverified user gets into the verified routes.
#[tracing::instrument(name = "ResendVerification", skip(scheme, claims))]
pub async fn resend_verification<S, C>(
    State(scheme): State<S>,
    Extension(claims): Extension<C>,
) -> impl IntoResponse
where
    S: RequiresEmailVerification,
    S::EmailVerificationError: IntoStatusMessage,
    C: IdentityClaims + Clone + Send + Sync + 'static,
{
    let email = match Email::try_from(claims.subject().clone()) {
        Ok(email) => email,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    match scheme.initiate_email_verification(email).await {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "success" })),
        )
            .into_response(),
        Err(e) => {
            let (status, message) = e.into_status_message();
            (status, Json(serde_json::json!({ "error": message }))).into_response()
        }
    }
}
