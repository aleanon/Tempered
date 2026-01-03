//! Axum middleware for authentication.
//!
//! Provides middleware for validating tokens and extracting claims.

use axum::{
    Json,
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use tempered_core::{AuthValidator, AuthenticationScheme, HttpElevationScheme};

/// Middleware that validates an elevated token and extracts claims into the request extensions.
///
/// This middleware:
/// 1. Splits the request into parts
/// 2. Validates the elevated token using the scheme's validator
/// 3. Extracts claims from the token
/// 4. Inserts claims into request extensions for downstream handlers
///
/// If validation fails, returns 401 Unauthorized.
pub async fn validate_elevated_token<S>(
    State(scheme): State<S>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, ElevatedTokenError>
where
    S: HttpElevationScheme + AuthenticationScheme + Clone + Send + Sync + 'static,
    S::Validator: AuthValidator<RequestParts = http::request::Parts>,
{
    // Split the request into parts (headers, method, URI, etc.) and body
    let (mut parts, body) = req.into_parts();

    // Validate using the scheme's validator which expects request parts
    let claims = scheme
        .validator()
        .validate(&parts)
        .await
        .map_err(|e| ElevatedTokenError::InvalidToken(e.to_string()))?;

    // Insert claims into request extensions
    parts.extensions.insert(claims);

    // Reconstruct the request with the claims in extensions
    let req = Request::from_parts(parts, body);

    // Continue to the next handler
    Ok(next.run(req).await)
}

/// Errors that can occur during elevated token validation in middleware
#[derive(Debug)]
pub enum ElevatedTokenError {
    InvalidToken(String),
}

impl IntoResponse for ElevatedTokenError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ElevatedTokenError::InvalidToken(msg) => {
                // Check if the error is about a missing token
                if msg.contains("Missing") || msg.contains("No cookie") || msg.contains("not found")
                {
                    (StatusCode::BAD_REQUEST, msg)
                } else {
                    (StatusCode::UNAUTHORIZED, msg)
                }
            }
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}
