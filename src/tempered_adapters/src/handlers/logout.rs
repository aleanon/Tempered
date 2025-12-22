//! Framework-agnostic logout handler.

use tempered_core::{
    AuthRequest, AuthResponseBuilder, HttpAuthenticationScheme, SupportsTokenRevocation,
};

/// Handle logout request - framework agnostic.
///
/// This function contains the pure logout logic without any framework dependencies.
/// Framework-specific routes call this after extracting the request.
///
/// # Arguments
///
/// * `scheme` - The authentication scheme to use
/// * `request` - The HTTP request (implements AuthRequest trait)
/// * `builder` - Response builder (framework-specific but implements our trait)
///
/// # Returns
///
/// Returns either a successful logout response or an error message.
///
/// # Example
///
/// ```ignore
/// // In an Axum route:
/// pub async fn axum_logout(
///     State(scheme): State<JwtScheme>,
///     req: Request<Body>,
/// ) -> Result<Response, LogoutError> {
///     let builder = response_builder();
///     handle_logout(&scheme, &req, builder)
///         .await
///         .map_err(|e| LogoutError::from(e))
/// }
/// ```
pub async fn handle_logout<S, R, B>(
    scheme: &S,
    request: &R,
    builder: B,
) -> Result<B::Response, String>
where
    S: HttpAuthenticationScheme + SupportsTokenRevocation,
    R: AuthRequest,
    B: AuthResponseBuilder,
{
    // Extract token from request (scheme decides where to look: cookie, header, etc.)
    let token = scheme
        .extract_token_from_request(request)
        .ok_or_else(|| "Missing authentication token".to_string())?;

    // Revoke the token (domain logic)
    scheme
        .revoke_token(&token)
        .await
        .map_err(|e| format!("Token revocation failed: {}", e))?;

    // Create the logout response
    Ok(scheme.create_logout_response(builder, None))
}
