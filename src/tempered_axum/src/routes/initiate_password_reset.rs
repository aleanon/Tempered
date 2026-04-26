use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use secrecy::Secret;
use serde::Deserialize;
use tempered_core::{Email, SupportsPasswordReset};

#[tracing::instrument(name = "Initiate Password Reset", skip(scheme, request))]
pub async fn initiate_password_reset<S>(
    State(scheme): State<S>,
    Json(request): Json<InitiatePasswordResetRequest>,
) -> impl IntoResponse
where
    S: SupportsPasswordReset + Send + Sync + Clone + 'static,
{
    // Parse email — on failure, still return 200 to prevent enumeration.
    if let Ok(email) = Email::try_from(request.email) {
        let _ = scheme.initiate_password_reset(email).await;
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "success",
            "message": "If that email address is registered, you will receive a password reset link"
        })),
    )
}

#[derive(Debug, Deserialize)]
pub struct InitiatePasswordResetRequest {
    pub email: Secret<String>,
}
