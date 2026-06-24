//! Framework-agnostic OAuth2 / OIDC handlers.
//!
//! Like the other handlers, these contain the pure flow logic; framework routes
//! extract the provider / query params / state cookie and convert the result.

use tempered_core::{HttpOAuth2Scheme, ResponseBuilder};

/// Begin an OAuth flow: redirect to the provider and bind the `state` cookie.
pub async fn handle_oauth_start<S, B>(
    scheme: &S,
    provider: &str,
    builder: B,
) -> Result<B::Response, S::OAuth2Error>
where
    S: HttpOAuth2Scheme,
    B: ResponseBuilder,
{
    let authorization = scheme.begin_oauth(provider).await?;
    Ok(scheme
        .create_oauth_start_response(builder, authorization)
        .expect(
            "ResponseBuilder error in create_oauth_start_response - this is a bug in the scheme implementation",
        ))
}

/// Complete an OAuth callback: issue the primary token and redirect into the app.
pub async fn handle_oauth_callback<S, B>(
    scheme: &S,
    provider: &str,
    code: &str,
    query_state: &str,
    cookie_state: &str,
    builder: B,
) -> Result<B::Response, S::OAuth2Error>
where
    S: HttpOAuth2Scheme,
    B: ResponseBuilder,
{
    let token = scheme
        .complete_oauth(provider, code, query_state, cookie_state)
        .await?;
    Ok(scheme
        .create_oauth_callback_response(builder, token)
        .expect(
            "ResponseBuilder error in create_oauth_callback_response - this is a bug in the scheme implementation",
        ))
}
