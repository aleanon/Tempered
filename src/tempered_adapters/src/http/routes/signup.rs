use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use secrecy::Secret;
use serde::Deserialize;
use tempered_application::SignupUseCase;
use tempered_core::{Email, Password, UserStore};

use super::error::AuthApiError;

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: Secret<String>,
    pub password: Secret<String>,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[tracing::instrument(name = "Signup", skip_all)]
pub async fn signup<U>(
    State(user_store): State<U>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthApiError>
where
    U: UserStore + Clone + 'static,
{
    let use_case = SignupUseCase::new(user_store);

    let email = Email::try_from(request.email)?;
    let password = Password::try_from(request.password)?;

    use_case
        .execute(email, password, request.requires_2fa)
        .await?;

    Ok((
        StatusCode::CREATED,
        String::from("User created successfully!"),
    ))
}
