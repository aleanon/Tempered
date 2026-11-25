//! Tier checks for the app's own routes.
//!
//! The library's routes check their tier inside
//! [`Endpoints::handle`](tempered_adapters::endpoints::Endpoints::handle).
//! The app's routers (`validated_router`, `verified_router`,
//! `validated_elevated_router`) get the same checks here, from the same
//! functions, plus the typed claims in the request extensions
//! (`Extension<Claims>`).

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use tempered_adapters::endpoints::{self, Endpoints};
use tempered_core::{
    AuthValidator, AuthenticationScheme, ClassifyError, IdentityClaims, SupportsElevation,
};

use crate::adapters::into_axum_response;

// `Result<Response, Response>` is the shape `axum::middleware::from_fn_with_state`
// expects from a rejecting middleware; boxing the error would only add an
// allocation on the rejection path.

/// Admit requests with a valid login token, and put its claims in the
/// request extensions.
#[allow(clippy::result_large_err)]
pub async fn validate_token<S>(
    State(scheme): State<S>,
    req: Request,
    next: Next,
) -> Result<Response, Response>
where
    S: AuthenticationScheme + Clone + Send + Sync + 'static,
    S::Validator: AuthValidator<RequestParts = http::request::Parts>,
    <S::Validator as AuthValidator>::Error: ClassifyError,
{
    let (mut parts, body) = req.into_parts();
    let claims = endpoints::validate_login(&scheme, &parts)
        .await
        .map_err(into_axum_response)?;
    parts.extensions.insert(claims);
    Ok(next.run(Request::from_parts(parts, body)).await)
}

/// Admit requests with a valid elevated token, and put its claims in the
/// request extensions.
#[allow(clippy::result_large_err)]
pub async fn validate_elevated_token<S>(
    State(scheme): State<S>,
    req: Request,
    next: Next,
) -> Result<Response, Response>
where
    S: SupportsElevation + Clone + Send + Sync + 'static,
    S::ElevatedValidator: AuthValidator<RequestParts = http::request::Parts>,
    <S::ElevatedValidator as AuthValidator>::Error: ClassifyError,
{
    let (mut parts, body) = req.into_parts();
    let claims = endpoints::validate_elevated(&scheme, &parts)
        .await
        .map_err(into_axum_response)?;
    parts.extensions.insert(claims);
    Ok(next.run(Request::from_parts(parts, body)).await)
}

/// Admit only users whose address is verified (or every logged-in user, if
/// the scheme has no email verification). Runs inside [`validate_token`]:
/// it reads the claims that one inserted, and rejects with 401 if there are
/// none. The address is looked up per request, so verifying takes effect at
/// once.
#[allow(clippy::result_large_err)]
pub async fn require_verified_email<S>(
    State(scheme): State<S>,
    req: Request,
    next: Next,
) -> Result<Response, Response>
where
    S: AuthenticationScheme + Endpoints + Clone + Send + Sync + 'static,
    S::Validator: AuthValidator<RequestParts = http::request::Parts>,
    <S::Validator as AuthValidator>::Claims: IdentityClaims,
{
    let not_logged_in = || {
        into_axum_response(endpoints::error_response(
            http::StatusCode::UNAUTHORIZED,
            "Not logged in",
        ))
    };
    let claims = req
        .extensions()
        .get::<<S::Validator as AuthValidator>::Claims>()
        .ok_or_else(not_logged_in)?;
    let email = endpoints::subject_email(claims).map_err(into_axum_response)?;
    scheme
        .check_verified(&email)
        .await
        .map_err(into_axum_response)?;
    Ok(next.run(req).await)
}

/// Refuse state-changing requests (anything but GET and HEAD) sent by a
/// page on another site, with 403. The library's own routes already do this
/// (see [`endpoints::is_cross_site`] for the rules); layer it over an app
/// router that should do the same:
///
/// ```ignore
/// Router::new()
///     .route("/settings", post(save))
///     .layer(axum::middleware::from_fn(tempered_axum::middleware::refuse_cross_site))
/// ```
#[allow(clippy::result_large_err)]
pub async fn refuse_cross_site(req: Request, next: Next) -> Result<Response, Response> {
    let safe = matches!(*req.method(), http::Method::GET | http::Method::HEAD);
    let (parts, body) = req.into_parts();
    if !safe && endpoints::is_cross_site(&parts) {
        return Err(into_axum_response(endpoints::cross_site_refused()));
    }
    Ok(next.run(Request::from_parts(parts, body)).await)
}

/// Admit a request authenticated with an API key that carries `scope`.
/// Runs after the key check (`validate_token::<ApiKeyScheme<..>>`, which
/// puts the claims in the extensions): no claims is a `401`, a key without
/// the scope a `403`.
///
/// ```ignore
/// Router::new()
///     .route("/invoices", get(list_invoices))
///     .layer(axum::middleware::from_fn(|req, next| require_scope("invoices:read", req, next)))
///     .layer(axum::middleware::from_fn_with_state(keys.clone(), validate_token::<Keys>));
/// ```
pub async fn require_scope(scope: &'static str, req: Request, next: Next) -> Response {
    use axum::response::IntoResponse;
    use tempered_adapters::authentication::api_key_scheme::ApiKeyClaims;
    match req.extensions().get::<ApiKeyClaims>() {
        None => (
            http::StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({ "error": "Missing API key" })),
        )
            .into_response(),
        Some(claims) if !claims.has_scope(scope) => (
            http::StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({ "error": format!("This key lacks the {scope} scope") })),
        )
            .into_response(),
        Some(_) => next.run(req).await,
    }
}
