//! Framework-agnostic handler for privilege elevation.
//!
//! This handler implements the "sudo" pattern - users must re-authenticate
//! with their password to receive an elevated token for sensitive operations.

use tempered_core::{
    ClassifyError, Email, ErrorCategory, HttpElevationScheme, Password, ResponseBuilder,
};

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
/// Either an HTTP response with the elevated token, or the error's category
/// and client-safe message (from [`ClassifyError`]; internal detail is
/// logged, never returned).
pub async fn handle_elevate<S, B>(
    scheme: &S,
    email: Email,
    password: Password,
    builder: B,
) -> Result<B::Response, (ErrorCategory, String)>
where
    S: HttpElevationScheme,
    S::ElevationError: ClassifyError,
    B: ResponseBuilder,
{
    // Re-authenticate the user to create elevated token
    let elevated_token = scheme
        .elevate(email, password)
        .await
        .map_err(ClassifyError::classify)?;

    // Create HTTP response with elevated token
    scheme
        .create_elevation_response(builder, elevated_token)
        .map_err(|e| {
            tracing::error!(error = %e, "failed to build the elevation response");
            (ErrorCategory::Internal, "Internal error".to_string())
        })
}
