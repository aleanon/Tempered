//! Framework-agnostic handler for privilege elevation.
//!
//! This handler implements the "sudo" pattern - users must re-authenticate
//! with their password to receive an elevated token for sensitive operations.

use tempered_core::{AuthResponseBuilder, Email, HttpElevationScheme, Password, SupportsElevation};

/// Framework-agnostic elevation handler.
///
/// Takes user credentials, re-authenticates them, and returns an elevated token
/// with a shorter expiry time for sensitive operations.
///
/// # Type Parameters
/// * `S` - Authentication scheme that supports elevation
/// * `B` - Response builder for the framework being used
///
/// # Arguments
/// * `scheme` - The authentication scheme instance
/// * `email` - User's email address
/// * `password` - User's password for re-authentication
/// * `builder` - HTTP response builder
///
/// # Returns
/// Either an HTTP response with the elevated token, or an error message
pub async fn handle_elevate<S, B>(
    scheme: &S,
    email: Email,
    password: Password,
    builder: B,
) -> Result<B::Response, String>
where
    S: HttpElevationScheme + SupportsElevation,
    B: AuthResponseBuilder,
{
    // Re-authenticate the user to create elevated token
    let elevated_token = scheme
        .elevate(email, password)
        .await
        .map_err(|e| format!("Elevation failed: {}", e))?;

    // Create HTTP response with elevated token
    Ok(scheme.create_elevation_response(builder, elevated_token))
}
