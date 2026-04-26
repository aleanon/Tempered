use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use secrecy::Secret;
use serde::Deserialize;
use tempered_core::{Password, SupportsPasswordReset};
use thiserror::Error;

#[tracing::instrument(name = "Complete Password Reset", skip(scheme, request))]
pub async fn complete_password_reset<S>(
    State(scheme): State<S>,
    Json(request): Json<CompletePasswordResetRequest>,
) -> Result<impl IntoResponse, CompletePasswordResetError>
where
    S: SupportsPasswordReset + Send + Sync + Clone + 'static,
{
    let new_password = Password::try_from(request.new_password)
        .map_err(|e| CompletePasswordResetError::InvalidPassword(e.to_string()))?;

    scheme
        .complete_password_reset(request.reset_token, new_password)
        .await
        .map_err(|e| CompletePasswordResetError::Failed(e.to_string()))?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "success",
            "message": "Password reset successfully"
        })),
    ))
}

#[derive(Debug, Deserialize)]
pub struct CompletePasswordResetRequest {
    pub reset_token: String,
    pub new_password: Secret<String>,
}

#[derive(Debug, Error)]
pub enum CompletePasswordResetError {
    #[error("Invalid password: {0}")]
    InvalidPassword(String),

    #[error("Reset failed: {0}")]
    Failed(String),
}

impl IntoResponse for CompletePasswordResetError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            CompletePasswordResetError::InvalidPassword(msg) => (StatusCode::BAD_REQUEST, msg),
            CompletePasswordResetError::Failed(msg) => (StatusCode::BAD_REQUEST, msg),
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}
