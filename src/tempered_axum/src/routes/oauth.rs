//! Axum-specific OAuth2 / OIDC routes (start + callback).
//!
//! Both are `GET` routes (the browser is redirected through them) and carry a
//! `{provider}` path segment, so one pair of routes serves every configured
//! provider.

use axum::{
    Json,
    extract::{Path, Query, State},
    response::IntoResponse,
};
use serde::Deserialize;
use tempered_adapters::{handlers, http::HttpResponseBuilder};
use tempered_core::{AuthRequest, HttpOAuth2Scheme};
use crate::IntoStatusMessage;

use crate::adapters::{AuthRequestExtractor, into_axum_response};

/// Query parameters the provider sends back on the callback.
#[derive(Debug, Deserialize)]
pub struct OAuthCallbackParams {
    pub code: String,
    pub state: String,
}

/// Leg 1: begin the flow for `{provider}` and redirect to the provider, setting
/// the `state` binding cookie.
#[tracing::instrument(name = "OAuthStart", skip(scheme))]
pub async fn oauth_start<S>(
    State(scheme): State<S>,
    Path(provider): Path<String>,
) -> impl IntoResponse
where
    S: HttpOAuth2Scheme,
    S::OAuth2Error: IntoStatusMessage,
{
    let builder = HttpResponseBuilder::new();

    match handlers::handle_oauth_start(&scheme, &provider, builder).await {
        Ok(http_response) => into_axum_response(http_response).into_response(),
        Err(e) => {
            let (status, message) = e.into_status_message();
            (status, Json(serde_json::json!({ "error": message }))).into_response()
        }
    }
}

/// Leg 2: complete the callback. The `state` query parameter must match the
/// browser-bound `state` cookie; on success the scheme's auth cookie is set and
/// the browser is redirected into the app.
#[tracing::instrument(name = "OAuthCallback", skip(scheme, req))]
pub async fn oauth_callback<S>(
    State(scheme): State<S>,
    Path(provider): Path<String>,
    Query(params): Query<OAuthCallbackParams>,
    req: AuthRequestExtractor,
) -> impl IntoResponse
where
    S: HttpOAuth2Scheme,
    S::OAuth2Error: IntoStatusMessage,
{
    // The browser-bound state lives in the cookie the start leg set.
    let cookie_state = req
        .cookie(scheme.oauth_state_cookie_name())
        .unwrap_or("")
        .to_string();

    let builder = HttpResponseBuilder::new();

    match handlers::handle_oauth_callback(
        &scheme,
        &provider,
        &params.code,
        &params.state,
        &cookie_state,
        builder,
    )
    .await
    {
        Ok(http_response) => into_axum_response(http_response).into_response(),
        Err(e) => {
            let (status, message) = e.into_status_message();
            (status, Json(serde_json::json!({ "error": message }))).into_response()
        }
    }
}
