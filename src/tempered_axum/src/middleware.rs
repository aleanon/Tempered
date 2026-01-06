//! Axum middleware for authentication.
//!
//! Provides middleware for validating tokens and extracting claims.

use axum::{
    Json,
    body::Body,
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tempered_core::{
    AuthValidator, AuthenticationScheme, HttpElevationScheme, IntoStatusMessage, SupportsElevation,
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
