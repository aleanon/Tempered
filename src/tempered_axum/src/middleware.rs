//! Axum middleware for authentication.
//!
//! Provides middleware for validating tokens and extracting claims.

use crate::IntoStatusMessage;
use axum::{
    Json,
    body::Body,
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tempered_core::{
    AuthValidator, AuthenticationScheme, Email, HttpElevationScheme, IdentityClaims,
    RequiresEmailVerification, SupportsElevation,
};

/// Middleware that validates a regular token and extracts claims into the request extensions.
///
/// This middleware:
/// 1. Splits the request into parts
/// 2. Validates the elevated token using the scheme's validator
/// 3. Extracts claims from the token
/// 4. Inserts claims into request extensions for downstream handlers
///
/// If validation fails, returns 401 Unauthorized.
// `Result<Response, Response>` is the shape `axum::middleware::from_fn_with_state`
// expects from a rejecting middleware; boxing the error would only add an
// allocation on the rejection path.
#[allow(clippy::result_large_err)]
pub async fn validate_token<S>(
    State(scheme): State<S>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, Response>
where
    S: AuthenticationScheme + Clone + Send + Sync + 'static,
    S::Validator: AuthValidator<RequestParts = http::request::Parts>,
    <S::Validator as AuthValidator>::Error: IntoStatusMessage,
{
    // Split the request into parts (headers, method, URI, etc.) and body
    let (mut parts, body) = req.into_parts();

    // Validate using the scheme's validator which expects request parts
    let claims = scheme.validator().validate(&parts).await.map_err(|e| {
        let (status, message) = e.into_status_message();
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    })?;

    // Insert claims into request extensions
    parts.extensions.insert(claims);

    // Reconstruct the request with the claims in extensions
    let req = Request::from_parts(parts, body);

    // Continue to the next handler
    Ok(next.run(req).await)
}

/// Middleware that validates an elevated token and extracts claims into the request extensions.
///
/// This middleware:
/// 1. Splits the request into parts
/// 2. Validates the elevated token using the scheme's elevated validator
/// 3. Extracts claims from the token
/// 4. Inserts claims into request extensions for downstream handlers
///
/// Elevated tokens are required for sensitive operations like password changes and account deletion.
/// If validation fails, returns the appropriate error status.
// `Result<Response, Response>` is the shape `axum::middleware::from_fn_with_state`
// expects from a rejecting middleware; boxing the error would only add an
// allocation on the rejection path.
#[allow(clippy::result_large_err)]
pub async fn validate_elevated_token<S>(
    State(scheme): State<S>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, Response>
where
    S: HttpElevationScheme
        + AuthenticationScheme
        + SupportsElevation
        + Clone
        + Send
        + Sync
        + 'static,
    S::ElevatedValidator: AuthValidator<RequestParts = http::request::Parts>,
    <S::ElevatedValidator as AuthValidator>::Error: IntoStatusMessage,
{
    // Split the request into parts (headers, method, URI, etc.) and body
    let (mut parts, body) = req.into_parts();

    // Validate using the scheme's elevated validator which expects request parts
    let claims = scheme
        .elevated_validator()
        .validate(&parts)
        .await
        .map_err(|e| {
            let (status, message) = e.into_status_message();
            (status, Json(serde_json::json!({ "error": message }))).into_response()
        })?;

    // Insert claims into request extensions
    parts.extensions.insert(claims);

    // Reconstruct the request with the claims in extensions
    let req = Request::from_parts(parts, body);

    // Continue to the next handler
    Ok(next.run(req).await)
}

/// Middleware that admits only users whose email address is verified.
///
/// Runs inside the login middleware (it reads the claims that one inserted) on
/// the verified bucket. The address is looked up on every request, so a
/// verification takes effect at once, without a new login.
///
/// Rejects with 403 if the address is not verified, 401 if there are no
/// claims (the route was mounted without the login middleware in front).
#[allow(clippy::result_large_err)]
pub async fn require_verified_email<S>(
    State(scheme): State<S>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, Response>
where
    S: AuthenticationScheme + RequiresEmailVerification + Clone + Send + Sync + 'static,
    S::Validator: AuthValidator<RequestParts = http::request::Parts>,
    <S::Validator as AuthValidator>::Claims: IdentityClaims,
    S::EmailVerificationError: IntoStatusMessage,
{
    let reject = |status: http::StatusCode, message: &str| {
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    };

    let claims = req
        .extensions()
        .get::<<S::Validator as AuthValidator>::Claims>()
        .ok_or_else(|| reject(http::StatusCode::UNAUTHORIZED, "Not logged in"))?;
    let email = Email::try_from(claims.subject().clone())
        .map_err(|_| reject(http::StatusCode::UNAUTHORIZED, "Not logged in"))?;

    match scheme.is_email_verified(&email).await {
        Ok(true) => Ok(next.run(req).await),
        Ok(false) => Err(reject(
            http::StatusCode::FORBIDDEN,
            "Email address not verified",
        )),
        Err(e) => {
            let (status, message) = e.into_status_message();
            Err(reject(status, &message))
        }
    }
}
