//! Axum-specific login route.

use axum::{Json, extract::State, response::IntoResponse};
use tempered_adapters::{handlers, http::HttpResponseBuilder};
use tempered_core::{HttpAuthenticationScheme, IntoStatusMessage};

use crate::adapters::into_axum_response;

/// Axum login route.
///
/// This route is Axum-specific - it uses Axum's extractors and error handling.
/// The actual authentication logic is in the framework-agnostic handler.
#[tracing::instrument(name = "Login", skip(scheme, credentials))]
pub async fn login<S>(
    State(scheme): State<S>,
    Json(credentials): Json<S::Credentials>,
) -> impl IntoResponse
where
    S: HttpAuthenticationScheme,
    S::AuthError: IntoStatusMessage,
{
    let builder = HttpResponseBuilder::new();

    match handlers::handle_login(&scheme, credentials, builder).await {
        Ok(http_response) => into_axum_response(http_response).into_response(),
        Err(e) => {
            let (status, message) = e.into_status_message();
            (status, Json(serde_json::json!({ "error": message }))).into_response()
        }
    }
}
