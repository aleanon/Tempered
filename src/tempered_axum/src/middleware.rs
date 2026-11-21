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
