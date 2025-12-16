use auth_application::Verify2FaUseCase;
use auth_core::{Email, TwoFaAttemptId, TwoFaCode, TwoFaCodeStore};
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;
use secrecy::Secret;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::auth::generate_auth_cookie;
use crate::config::AuthServiceSetting;

use super::error::AuthApiError;

#[derive(Debug, Deserialize)]
pub struct Verify2FARequest {
    pub email: Secret<String>,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
    #[serde(rename = "2FACode")]
    pub two_factor_code: String,
}

#[tracing::instrument(name = "Verify 2FA", skip_all)]
pub async fn verify_2fa<T>(
    State(two_fa_code_store): State<Arc<RwLock<T>>>,
    jar: CookieJar,
    Json(request): Json<Verify2FARequest>,
) -> Result<impl IntoResponse, AuthApiError>
where
    T: TwoFaCodeStore + 'static,
{
    let config = AuthServiceSetting::load();

    // Parse domain entities
    let email = Email::try_from(request.email)?;
    let login_attempt_id = TwoFaAttemptId::parse(&request.login_attempt_id)?;
    let two_fa_code = TwoFaCode::parse(request.two_factor_code)?;

    // Use the verify 2FA use case
    let use_case = Verify2FaUseCase::new(two_fa_code_store);
    let verified_email = use_case
        .execute(email, login_attempt_id, two_fa_code)
        .await?;

    // Generate auth cookie
    let auth_cookie = generate_auth_cookie(&verified_email, &config)?;
    let updated_jar = jar.add(auth_cookie);

    Ok((updated_jar, StatusCode::OK))
}
