use axum::{Json, extract::State, response::IntoResponse};
use serde::Deserialize;
use tempered_adapters::{handlers, http::HttpResponseBuilder};
use tempered_core::{IntoStatusMessage, RequiresEmailVerification};

use crate::adapters::into_axum_response;

#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[tracing::instrument(name = "VerifyEmail", skip(scheme, request))]
pub async fn verify_email<S>(
    State(scheme): State<S>,
    Json(request): Json<VerifyEmailRequest>,
) -> impl IntoResponse
where
    S: RequiresEmailVerification,
    S::EmailVerificationError: IntoStatusMessage,
{
    let builder = HttpResponseBuilder::new();

    match handlers::handle_verify_email(&scheme, request.token, builder).await {
        Ok(http_response) => into_axum_response(http_response).into_response(),
        Err(e) => {
            let (status, message) = e.into_status_message();
            (status, Json(serde_json::json!({ "error": message }))).into_response()
        }
    }
}
