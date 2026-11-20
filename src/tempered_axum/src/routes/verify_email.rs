use crate::IntoStatusMessage;
use axum::{Extension, Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Deserialize;
use tempered_adapters::{handlers, http::HttpResponseBuilder};
use tempered_core::{Email, IdentityClaims, RequiresEmailVerification};

use crate::adapters::into_axum_response;

#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

/// Verify the logged-in user's address with the token from their email.
///
/// Login-gated: the link alone would let the inbox owner verify an account
/// someone else created with their address (and its password). A frontend
/// that opens the link without a session sends the user to log in first and
/// then posts the token here.
#[tracing::instrument(name = "VerifyEmail", skip(scheme, claims, request))]
pub async fn verify_email<S, C>(
    State(scheme): State<S>,
    Extension(claims): Extension<C>,
    Json(request): Json<VerifyEmailRequest>,
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
    let builder = HttpResponseBuilder::new();

    match handlers::handle_verify_email(&scheme, &email, request.token, builder).await {
        Ok(http_response) => into_axum_response(http_response).into_response(),
        Err(e) => {
            let (status, message) = e.into_status_message();
            (status, Json(serde_json::json!({ "error": message }))).into_response()
        }
    }
}
