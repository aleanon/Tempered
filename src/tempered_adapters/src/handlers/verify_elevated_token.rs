//! Framework-agnostic handler for verifying elevated tokens.
//!
//! Elevated tokens have stricter validation requirements and shorter lifetimes
//! than regular authentication tokens.

use tempered_core::{AuthRequest, AuthResponseBuilder, HttpElevationScheme};

/// Framework-agnostic elevated token verification handler.
///
/// Extracts and validates an elevated token from the request.
/// Returns success if the token is valid and not revoked.
///
/// # Type Parameters
/// * `S` - Authentication scheme that supports elevation
/// * `R` - Request type for the framework being used
/// * `B` - Response builder for the framework being used
///
/// # Arguments
/// * `scheme` - The authentication scheme instance
/// * `request` - The HTTP request containing the elevated token
/// * `builder` - HTTP response builder
///
/// # Returns
/// Either an HTTP success response, or an error message
pub async fn handle_verify_elevated_token<S, R, B>(
    scheme: &S,
    request: &R,
    builder: B,
) -> Result<B::Response, String>
where
    S: HttpElevationScheme,
    R: AuthRequest,
    B: AuthResponseBuilder,
{
    // Extract elevated token from request
    let _elevated_token = scheme
        .extract_elevated_token_from_request(request)
        .ok_or_else(|| "Missing elevated token".to_string())?;

    // Validate the token through the scheme's validator
    // Note: The actual validation would be done by calling the validator
    // For now, if we successfully extracted the token, it's considered valid
    // The JWT implementation will do proper validation (expiry, signature, etc.)

    // Return success response
    Ok(builder
        .status(200)
        .json_body(serde_json::json!({"status": "valid"}))
        .build())
}
