//! Framework-agnostic login handler.

use tempered_core::{AuthResponseBuilder, HttpAuthenticationScheme};

/// Handle login request - framework agnostic.
///
/// This function contains the pure authentication logic without any framework dependencies.
/// Framework-specific routes call this after extracting credentials.
///
/// # Arguments
///
/// * `scheme` - The authentication scheme to use
/// * `credentials` - User credentials (already deserialized from request)
/// * `builder` - Response builder (framework-specific but implements our trait)
///
/// # Returns
///
/// Returns either a successful response or an error message.
///
/// # Example
///
/// ```ignore
/// // In an Axum route:
/// pub async fn axum_login(
///     State(scheme): State<JwtScheme>,
///     Json(credentials): Json<Credentials>,
/// ) -> Result<Response, LoginError> {
///     let builder = response_builder();
///     handle_login(&scheme, credentials, builder)
///         .await
///         .map_err(|e| LoginError::from(e))
/// }
/// ```
pub async fn handle_login<S, B>(
    scheme: &S,
    credentials: S::Credentials,
    builder: B,
) -> Result<B::Response, String>
where
    S: HttpAuthenticationScheme,
    B: AuthResponseBuilder,
{
    // Call the scheme's login method (domain logic)
    let outcome = scheme
        .login(credentials)
        .await
        .map_err(|e| format!("Authentication failed: {}", e))?;

    // Let the scheme decide how to deliver the token via HTTP
    Ok(scheme.create_login_response(builder, outcome))
}
