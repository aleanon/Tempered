use auth_application::ElevateUseCase;
use auth_core::{BannedTokenStore, Email, Password, UserStore};
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;
use secrecy::Secret;
use serde::Deserialize;

use crate::auth::{generate_elevated_auth_cookie, validate_auth_token};
use crate::config::AuthServiceSetting;

use super::error::AuthApiError;

#[derive(Debug, Deserialize)]
pub struct ElevateRequest {
    pub email: Secret<String>,
    pub password: Secret<String>,
}

#[tracing::instrument(name = "Elevate auth", skip_all)]
pub async fn elevate<U, B>(
    State((user_store, banned_token_store)): State<(U, B)>,
    jar: CookieJar,
    Json(request): Json<ElevateRequest>,
) -> Result<impl IntoResponse, AuthApiError>
where
    U: UserStore + Clone + 'static,
    B: BannedTokenStore + Clone + 'static,
{
    let config = AuthServiceSetting::load();

    // Verify the user has a valid auth token first
    let cookie = jar
        .get(&config.auth.jwt.cookie_name)
        .ok_or(AuthApiError::MissingToken)?;

    validate_auth_token(cookie.value(), &banned_token_store).await?;

    // Parse domain entities
    let email = Email::try_from(request.email)?;
    let password = Password::try_from(request.password)?;

    // Use the elevate use case to re-authenticate
    let use_case = ElevateUseCase::new(user_store);
    let verified_email = use_case.execute(email, password).await?;

    // Generate elevated auth cookie
    let elevated_cookie = generate_elevated_auth_cookie(&verified_email, &config)?;

    Ok((jar.add(elevated_cookie), StatusCode::OK))
}
