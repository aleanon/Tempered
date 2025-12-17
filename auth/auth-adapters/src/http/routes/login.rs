use auth_application::{LoginResponse, LoginUseCase};
use auth_core::{Email, EmailClient, Password, TwoFaCodeStore, UserStore};
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;
use secrecy::Secret;
use serde::{Deserialize, Serialize};

use crate::auth::generate_auth_cookie;
use crate::config::AuthServiceSetting;

use super::error::AuthApiError;

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: Secret<String>,
    pub password: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginHttpResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub attempt_id: String,
}

#[tracing::instrument(name = "Login", skip_all)]
pub async fn login<U, T, E>(
    State((user_store, two_fa_store, email_client)): State<(U, T, E)>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthApiError>
where
    U: UserStore + Clone + 'static,
    T: TwoFaCodeStore + Clone + 'static,
    E: EmailClient + Clone + 'static,
{
    let use_case = LoginUseCase::new(user_store, two_fa_store, email_client);

    let email = Email::try_from(request.email)?;
    let password = Password::try_from(request.password)?;

    let login_response = use_case.execute(email, password).await?;

    match login_response {
        LoginResponse::Requires2Fa { attempt_id, .. } => {
            let two_factor_auth_response = TwoFactorAuthResponse {
                message: "2FA required".to_string(),
                attempt_id: attempt_id.to_string(),
            };

            Ok((
                jar,
                (
                    StatusCode::PARTIAL_CONTENT,
                    Json(LoginHttpResponse::TwoFactorAuth(two_factor_auth_response)),
                ),
            ))
        }
        LoginResponse::Success(email) => {
            let config = AuthServiceSetting::load();
            let auth_cookie = generate_auth_cookie(&email, &config)?;

            let jar = jar.add(auth_cookie);

            Ok((jar, (StatusCode::OK, Json(LoginHttpResponse::RegularAuth))))
        }
    }
}
