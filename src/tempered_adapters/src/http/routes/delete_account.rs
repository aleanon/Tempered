use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;
use tempered_application::DeleteAccountUseCase;
use tempered_core::{BannedTokenStore, Email, UserStore};

use crate::auth::{extract_token, validate_elevated_auth_token};

use super::error::AuthApiError;

#[tracing::instrument(name = "Delete Account", skip_all)]
pub async fn delete_account<U, B>(
    State((user_store, banned_token_store)): State<(U, B)>,
    jar: CookieJar,
) -> Result<impl IntoResponse, AuthApiError>
where
    U: UserStore + Clone + 'static,
    B: BannedTokenStore + Clone + 'static,
{
    let config = crate::config::AuthServiceSetting::load();
    let jwt_elevated_cookie_name = &config.auth.elevated_jwt.cookie_name;

    // Extract and validate elevated token
    let elevated_token = extract_token(&jar, jwt_elevated_cookie_name)?;
    let claims = validate_elevated_auth_token(elevated_token, &banned_token_store).await?;

    // Parse email from claims
    let user_email = Email::try_from(claims.sub)?;

    // Use the delete account use case
    let use_case = DeleteAccountUseCase::new(user_store);
    use_case.execute(user_email).await?;

    Ok((jar, StatusCode::NO_CONTENT))
}
