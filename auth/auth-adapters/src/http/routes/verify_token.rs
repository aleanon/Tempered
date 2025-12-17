use auth_core::BannedTokenStore;
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Deserialize;

use crate::auth::validate_auth_token;

use super::error::AuthApiError;

#[derive(Debug, Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}

#[tracing::instrument(name = "Verify Token", skip_all)]
pub async fn verify_token<B>(
    State(banned_token_store): State<B>,
    Json(token_request): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthApiError>
where
    B: BannedTokenStore + Clone + 'static,
{
    let banned_token_store = banned_token_store;

    // Validate the token - this checks if it's valid and not banned
    let _claims = validate_auth_token(&token_request.token, &banned_token_store).await?;

    Ok(StatusCode::OK)
}
