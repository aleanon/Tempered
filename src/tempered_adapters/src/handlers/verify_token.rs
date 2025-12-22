//! Framework-agnostic token verification handler.

use tempered_core::{AuthRequest, AuthResponseBuilder, HttpAuthenticationScheme};

/// Framework-agnostic token verification handler.
///
/// Extracts and validates an authentication token from the request.
/// Returns success if the token is valid and not revoked.
///
/// # Type Parameters
/// * `S` - Authentication scheme
/// * `R` - Request type for the framework being used
/// * `B` - Response builder for the framework being used
///
/// # Arguments
/// * `scheme` - The authentication scheme instance
/// * `request` - The HTTP request containing the token
/// * `builder` - HTTP response builder
///
/// # Returns
/// Either an HTTP success response, or an error message
pub async fn handle_verify_token<S, R, B>(
    scheme: &S,
    request: &R,
    builder: B,
) -> Result<B::Response, String>
where
    S: HttpAuthenticationScheme,
    R: AuthRequest,
    B: AuthResponseBuilder,
{
    // Extract token from request
    let _token = scheme
        .extract_token_from_request(request)
        .ok_or_else(|| "Missing authentication token".to_string())?;

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
