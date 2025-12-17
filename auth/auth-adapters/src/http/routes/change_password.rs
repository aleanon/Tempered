use auth_application::ChangePasswordUseCase;
use auth_core::{BannedTokenStore, Email, Password, UserStore};
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;
use secrecy::Secret;
use serde::Deserialize;

use crate::auth::{extract_token, validate_elevated_auth_token};

use super::error::AuthApiError;

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    new_password: Secret<String>,
}

#[tracing::instrument(name = "Change Password", skip_all)]
pub async fn change_password<U, B>(
    State((user_store, banned_token_store)): State<(U, B)>,
    jar: CookieJar,
    Json(request): Json<ChangePasswordRequest>,
) -> Result<impl IntoResponse, AuthApiError>
where
    U: UserStore + Clone + 'static,
    B: BannedTokenStore + Clone + 'static,
{
    let config = crate::config::AuthServiceSetting::load();
    let jwt_elevated_cookie_name = &config.auth.elevated_jwt.cookie_name;

    // Extract and validate elevated token
    let token = extract_token(&jar, jwt_elevated_cookie_name)?;
    let claim = validate_elevated_auth_token(token, &banned_token_store).await?;

    // Parse domain entities
    let email = Email::try_from(claim.sub)?;
    let new_password = Password::try_from(request.new_password)?;

    // Use the change password use case
    let use_case = ChangePasswordUseCase::new(user_store);
    use_case.execute(email, new_password).await?;

    Ok((jar, StatusCode::OK))
}
