use auth_application::LogoutUseCase;
use auth_core::BannedTokenStore;
use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::{CookieJar, cookie::Cookie};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::auth::{extract_token, validate_auth_token};
use crate::config::AuthServiceSetting;

use super::error::AuthApiError;

#[tracing::instrument(name = "Logout", skip_all)]
pub async fn logout<B>(
    State(banned_token_store): State<Arc<RwLock<B>>>,
    jar: CookieJar,
) -> Result<impl IntoResponse, AuthApiError>
where
    B: BannedTokenStore + 'static,
{
    let config = AuthServiceSetting::load();
    let jwt_cookie_name = config.auth.jwt.cookie_name.clone();
    let jwt_elevated_cookie_name = config.auth.elevated_jwt.cookie_name.clone();

    // Extract the main token (must be present)
    let token = extract_token(&jar, &jwt_cookie_name)?.to_owned();

    // Validate the token first
    validate_auth_token(&token, &*banned_token_store.read().await).await?;

    // Extract elevated token if present
    let elevated_token = jar
        .get(&jwt_elevated_cookie_name)
        .map(|cookie| cookie.value().to_owned());

    // Use the logout use case
    let use_case = LogoutUseCase::new(banned_token_store);
    use_case.execute(token, elevated_token).await?;

    // Remove both cookies - create removal cookies inline
    let has_elevated = jar.get(&jwt_elevated_cookie_name).is_some();
    let mut updated_jar = jar.remove(Cookie::from(jwt_cookie_name.clone()));
    if has_elevated {
        updated_jar = updated_jar.remove(Cookie::from(jwt_elevated_cookie_name));
    }

    Ok((updated_jar, StatusCode::OK))
}
