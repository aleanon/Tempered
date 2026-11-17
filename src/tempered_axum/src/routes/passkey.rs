//! Axum-specific passkey (WebAuthn) routes.
//!
//! Four `POST` routes, JSON in / JSON out: registration and authentication each
//! split into a `start` (returns `{ ceremony_id, options }`) and a `finish`
//! (takes `{ ceremony_id, response }` and verifies the authenticator response). A successful `login/finish` sets the scheme's auth
//! cookie, exactly like a password login.
//!
//! The two **registration** routes sit behind the login middleware — or, when
//! the scheme asks for it, the elevated ("sudo") middleware — and enroll a
//! passkey for the *authenticated* user, read from the claims that middleware
//! validated (`C`). They never accept an email from the request: a route that did would
//! let anyone attach their own authenticator to any account. The two **login**
//! routes are public.

use crate::IntoStatusMessage;
use axum::{Extension, Json, extract::State, http::StatusCode, response::IntoResponse};
use secrecy::Secret;
use serde::Deserialize;
use serde_json::json;
use tempered_adapters::{handlers, http::HttpResponseBuilder};
use tempered_core::{
    CeremonyId, Email, HttpAuthenticationScheme, IdentityClaims, SupportsPasskeys,
};

use crate::adapters::into_axum_response;

#[derive(Debug, Deserialize)]
pub struct LoginStartRequest {
    /// Omit for a usernameless (discoverable-credential) ceremony.
    #[serde(default)]
    pub email: Option<Secret<String>>,
}

#[derive(Debug, Deserialize)]
pub struct FinishRequest {
    /// The `ceremony_id` returned by the matching `start` route.
    pub ceremony_id: String,
    /// The credential `navigator.credentials` produced, as JSON.
    pub response: serde_json::Value,
}

fn bad_request(message: String) -> axum::response::Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response()
}

/// The logged-in user, from the claims the login middleware validated.
/// `None` only if the validated subject is somehow not an email.
fn session_email<C: IdentityClaims>(claims: &C) -> Option<Email> {
    Email::try_from(claims.subject().clone()).ok()
}

fn invalid_session() -> axum::response::Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "Invalid session" })),
    )
        .into_response()
}

/// Registration leg 1: issue creation options for the logged-in user.
///
/// Takes no request body; the user is the session owner.
#[tracing::instrument(name = "PasskeyRegisterStart", skip(scheme, claims))]
pub async fn passkey_register_start<S, C>(
    State(scheme): State<S>,
    Extension(claims): Extension<C>,
) -> impl IntoResponse
where
    S: SupportsPasskeys,
    S::PasskeyError: IntoStatusMessage,
    C: IdentityClaims + Clone + Send + Sync + 'static,
{
    let Some(email) = session_email(&claims) else {
        return invalid_session();
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

/// Registration leg 2: verify the attestation and enroll the credential for the
/// logged-in user, who must be the one that started the ceremony.
#[tracing::instrument(name = "PasskeyRegisterFinish", skip(scheme, claims, req))]
pub async fn passkey_register_finish<S, C>(
    State(scheme): State<S>,
    Extension(claims): Extension<C>,
    Json(req): Json<FinishRequest>,
) -> impl IntoResponse
where
    S: SupportsPasskeys,
    S::PasskeyError: IntoStatusMessage,
    C: IdentityClaims + Clone + Send + Sync + 'static,
{
    let Some(email) = session_email(&claims) else {
        return invalid_session();
    };

    let builder = HttpResponseBuilder::new();
    match handlers::handle_passkey_register_finish(
        &scheme,
        email,
        CeremonyId(req.ceremony_id),
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
        CeremonyId(req.ceremony_id),
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
