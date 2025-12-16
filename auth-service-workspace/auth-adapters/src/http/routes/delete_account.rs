use auth_application::DeleteAccountUseCase;
use auth_core::{BannedTokenStore, Email, UserStore};
use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::auth::{extract_token, validate_elevated_auth_token};

use super::error::AuthApiError;

#[tracing::instrument(name = "Delete Account", skip_all)]
pub async fn delete_account<U, B>(
    State((user_store, banned_token_store)): State<(Arc<RwLock<U>>, Arc<RwLock<B>>)>,
    jar: CookieJar,
) -> Result<impl IntoResponse, AuthApiError>
where
    U: UserStore + 'static,
    B: BannedTokenStore + 'static,
{
    let config = crate::config::AuthServiceSetting::load();
    let jwt_elevated_cookie_name = &config.auth.elevated_jwt.cookie_name;

    // Extract and validate elevated token
    let elevated_token = extract_token(&jar, jwt_elevated_cookie_name)?;
    let claims =
        validate_elevated_auth_token(elevated_token, &*banned_token_store.read().await).await?;

    // Parse email from claims
    let user_email = Email::try_from(claims.sub)?;

    // Use the delete account use case
    let use_case = DeleteAccountUseCase::new(user_store);
    use_case.execute(user_email).await?;

    Ok((jar, StatusCode::NO_CONTENT))
}
