//! Framework-agnostic logout handler.

use tempered_core::{
    AuthRequest, AuthResponseBuilder, HttpAuthenticationScheme, HttpElevationScheme,
    SupportsElevation, SupportsTokenRevocation,
};

/// Handle logout request - framework agnostic (base version without elevation support).
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
pub async fn handle_logout<S, R, B>(
    scheme: &S,
    request: &R,
    builder: B,
) -> Result<B::Response, String>
where
    S: HttpAuthenticationScheme<LogoutOutput = String>,
    R: AuthRequest,
    B: AuthResponseBuilder,
{
    // Extract regular token from request (scheme decides where to look: cookie, header, etc.)
    let token = scheme
        .extract_token_from_request(request)
        .ok_or_else(|| "Missing authentication token".to_string())?;

    // Logout using the scheme's logout method
    let cookie_name = scheme
        .logout(&token)
        .await
        .map_err(|e| format!("Logout failed: {}", e))?;

    // Create the logout response
    Ok(scheme.create_logout_response(builder, Some(cookie_name)))
}

/// Handle logout request with elevation support - framework agnostic.
///
/// This version also revokes elevated tokens if they exist.
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
pub async fn handle_logout_with_elevation<S, R, B>(
    scheme: &S,
    request: &R,
    builder: B,
) -> Result<B::Response, String>
where
    S: HttpAuthenticationScheme + HttpElevationScheme + SupportsElevation,
    R: AuthRequest,
    B: AuthResponseBuilder,
{
    // Extract regular token from request (scheme decides where to look: cookie, header, etc.)
    let token = scheme
        .extract_token_from_request(request)
        .ok_or_else(|| "Missing authentication token".to_string())?;

    // Revoke the regular token (domain logic)
    scheme
        .logout(&token)
        .await
        .map_err(|e| format!("Token revocation failed: {}", e))?;

    // Also try to revoke the elevated token if it exists
    // We don't fail if the elevated token is missing or invalid - it's optional
    if let Some(elevated_token) = scheme.extract_elevated_token_from_request(request) {
        // Silently ignore errors when revoking elevated token
        let _ = scheme.revoke_elevated_token(&elevated_token).await;
    }

    // Create the logout response
    Ok(scheme.create_logout_response(builder, None))
}
