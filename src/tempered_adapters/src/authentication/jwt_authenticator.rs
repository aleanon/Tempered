use async_trait::async_trait;
use axum_extra::extract::cookie::{self, Cookie};
use http::StatusCode;
use secrecy::Secret;
use serde::{Deserialize, Serialize};
use tempered_application::{
    LoginError, LoginResponse, LoginUseCase, SignupUseCase, Verify2FaError, Verify2FaUseCase,
};
use tempered_core::{
    Email, EmailClient, Password, TwoFaAttemptId, TwoFaCode, TwoFaCodeStore, TwoFaError, UserError,
    UserStore, UserStoreError,
    strategies::{auth_validator::AuthValidator, authenticator::Authenticator},
};
use thiserror::Error;

use crate::auth_validation::local_jwt_validator::{
    JwtAuthConfig, TokenAuthError, generate_auth_cookie,
};

#[derive(Debug, Error)]
pub enum JwtAuthError {
    #[error("{0}")]
    UserError(#[from] UserError),
    #[error("{0}")]
    TwoFaError(#[from] TwoFaError),
    #[error("{0}")]
    TokenAuthError(#[from] TokenAuthError),
    #[error("{0}")]
    UserStoreError(#[from] UserStoreError),
    #[error("{0}")]
    LoginError(#[from] LoginError),
    #[error("{0}")]
    Verify2FaError(#[from] Verify2FaError),
}

pub struct JwtAuthenticator<U, T, E, A> {
    user_store: U,
    two_fa_code_store: T,
    email_client: E,
    pub auth_validator: A,
    pub elevated_auth_validator: A,
    config: JwtAuthConfig,
}

#[async_trait]
impl<U, T, E, A> Authenticator for JwtAuthenticator<U, T, E, A>
where
    U: UserStore,
    T: TwoFaCodeStore,
    E: EmailClient,
    A: AuthValidator + Clone + Send + Sync,
    Self: 'static,
{
    type AuthValidator = A;
    type SignupRequest = SignupRequest;
    type SignupResponse = (StatusCode, String);
    type LoginRequest = LoginRequest;
    type LoginResponse = (StatusCode, LoginHttpResponse);
    type Verify2FaRequest = Verify2FARequest;
    type Verify2FaResponse = (StatusCode, Cookie<'static>);
    type Error = JwtAuthError;

    async fn signup(
        &self,
        request: Self::SignupRequest,
    ) -> Result<Self::SignupResponse, Self::Error> {
        let use_case = SignupUseCase::new(&self.user_store);

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

    async fn login(&self, request: Self::LoginRequest) -> Result<Self::LoginResponse, Self::Error> {
        let use_case = LoginUseCase::new(
            &self.user_store,
            &self.two_fa_code_store,
            &self.email_client,
        );

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
                    StatusCode::PARTIAL_CONTENT,
                    LoginHttpResponse::TwoFactorAuth(two_factor_auth_response),
                ))
            }
            LoginResponse::Success(email) => {
                let auth_cookie = generate_auth_cookie(&email, &self.config)?;

                Ok((
                    StatusCode::OK,
                    LoginHttpResponse::RegularAuth(auth_cookie.into_owned()),
                ))
            }
        }
    }

    async fn verify_2fa(
        &self,
        request: Self::Verify2FaRequest,
    ) -> Result<Self::Verify2FaResponse, Self::Error> {
        // Parse domain entities
        let email = Email::try_from(request.email)?;
        let login_attempt_id = TwoFaAttemptId::parse(&request.login_attempt_id)?;
        let two_fa_code = TwoFaCode::parse(request.two_factor_code)?;

        // Use the verify 2FA use case
        let use_case = Verify2FaUseCase::new(&self.two_fa_code_store);
        let verified_email = use_case
            .execute(email, login_attempt_id, two_fa_code)
            .await?;

        // Generate auth cookie
        let auth_cookie = generate_auth_cookie(&verified_email, &self.config)?;

        Ok((StatusCode::OK, auth_cookie.into_owned()))
    }

    async fn validator(&self) -> Self::AuthValidator {
        self.auth_validator.clone()
    }
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: Secret<String>,
    pub password: Secret<String>,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: Secret<String>,
    pub password: Secret<String>,
}

#[derive(Debug)]
pub enum LoginHttpResponse {
    RegularAuth(Cookie<'static>),
    TwoFactorAuth(TwoFactorAuthResponse),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub attempt_id: String,
}

#[derive(Debug, Deserialize)]
pub struct Verify2FARequest {
    pub email: Secret<String>,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
    #[serde(rename = "2FACode")]
    pub two_factor_code: String,
}
