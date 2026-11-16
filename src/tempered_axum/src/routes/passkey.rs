//! Axum-specific passkey (WebAuthn) routes.
//!
//! Four `POST` routes, JSON in / JSON out: registration and authentication each
//! split into a `start` (returns ceremony options) and a `finish` (verifies the
//! authenticator response). A successful `login/finish` sets the scheme's auth
//! cookie, exactly like a password login.

use crate::IntoStatusMessage;
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use secrecy::Secret;
use serde::Deserialize;
use serde_json::json;
use tempered_adapters::{handlers, http::HttpResponseBuilder};
use tempered_core::{Email, HttpAuthenticationScheme, SupportsPasskeys, WebAuthnChallenge};

use crate::adapters::into_axum_response;

#[derive(Debug, Deserialize)]
pub struct RegisterStartRequest {
    pub email: Secret<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginStartRequest {
    /// Omit for a usernameless (discoverable-credential) ceremony.
    #[serde(default)]
    pub email: Option<Secret<String>>,
}

#[derive(Debug, Deserialize)]
pub struct FinishRequest {
    pub challenge: String,
    pub response: serde_json::Value,
}

fn bad_request(message: String) -> axum::response::Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response()
}

/// Registration leg 1: issue creation options for an enrolling user.
#[tracing::instrument(name = "PasskeyRegisterStart", skip(scheme, req))]
pub async fn passkey_register_start<S>(
    State(scheme): State<S>,
    Json(req): Json<RegisterStartRequest>,
) -> impl IntoResponse
where
    S: SupportsPasskeys,
    S::PasskeyError: IntoStatusMessage,
{
    let email = match Email::try_from(req.email) {
        Ok(email) => email,
        Err(e) => return bad_request(e.to_string()),
    };

    let builder = HttpResponseBuilder::new();
    match handlers::handle_passkey_register_start(&scheme, email, builder).await {
        Ok(http_response) => into_axum_response(http_response).into_response(),
        Err(e) => {
            let (status, message) = e.into_status_message();
            (status, Json(json!({ "error": message }))).into_response()
        }
    }
}

/// Registration leg 2: verify the attestation and enroll the credential.
#[tracing::instrument(name = "PasskeyRegisterFinish", skip(scheme, req))]
pub async fn passkey_register_finish<S>(
    State(scheme): State<S>,
    Json(req): Json<FinishRequest>,
) -> impl IntoResponse
where
    S: SupportsPasskeys,
    S::PasskeyError: IntoStatusMessage,
{
    let builder = HttpResponseBuilder::new();
    match handlers::handle_passkey_register_finish(
        &scheme,
        WebAuthnChallenge(req.challenge),
        req.response,
        builder,
    )
    .await
    {
        Ok(http_response) => into_axum_response(http_response).into_response(),
        Err(e) => {
            let (status, message) = e.into_status_message();
            (status, Json(json!({ "error": message }))).into_response()
        }
    }
}

/// Authentication leg 1: issue request options.
#[tracing::instrument(name = "PasskeyLoginStart", skip(scheme, req))]
pub async fn passkey_login_start<S>(
    State(scheme): State<S>,
    Json(req): Json<LoginStartRequest>,
) -> impl IntoResponse
where
    S: SupportsPasskeys,
    S::PasskeyError: IntoStatusMessage,
{
    let email = match req.email.map(Email::try_from).transpose() {
        Ok(email) => email,
        Err(e) => return bad_request(e.to_string()),
    };

    let builder = HttpResponseBuilder::new();
    match handlers::handle_passkey_login_start(&scheme, email, builder).await {
        Ok(http_response) => into_axum_response(http_response).into_response(),
        Err(e) => {
            let (status, message) = e.into_status_message();
            (status, Json(json!({ "error": message }))).into_response()
        }
    }
}

/// Authentication leg 2: verify the assertion and set the auth cookie.
#[tracing::instrument(name = "PasskeyLoginFinish", skip(scheme, req))]
pub async fn passkey_login_finish<S>(
    State(scheme): State<S>,
    Json(req): Json<FinishRequest>,
) -> impl IntoResponse
where
    S: SupportsPasskeys + HttpAuthenticationScheme,
    S::PasskeyError: IntoStatusMessage,
{
    let builder = HttpResponseBuilder::new();
    match handlers::handle_passkey_login_finish(
        &scheme,
        WebAuthnChallenge(req.challenge),
        req.response,
        builder,
    )
    .await
    {
        Ok(http_response) => into_axum_response(http_response).into_response(),
        Err(e) => {
            let (status, message) = e.into_status_message();
            (status, Json(json!({ "error": message }))).into_response()
        }
    }
}
