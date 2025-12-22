//! Framework-agnostic 2FA verification handler.

use tempered_core::{
    AuthResponseBuilder, Email, HttpAuthenticationScheme, SupportsTwoFactor, TwoFaAttemptId,
    TwoFaCode,
};

/// Request data for 2FA verification.
///
/// This is a framework-agnostic representation of the 2FA verification request.
/// Framework-specific routes deserialize their request bodies into this type.
pub struct Verify2FaData {
    pub email: String,
    pub login_attempt_id: String,
    pub two_factor_code: String,
}

/// Handle 2FA verification request - framework agnostic.
///
/// This function contains the pure 2FA verification logic without any framework dependencies.
/// Framework-specific routes call this after deserializing the request body.
///
/// # Arguments
///
/// * `scheme` - The authentication scheme to use
/// * `data` - The 2FA verification data (email, attempt ID, code)
/// * `builder` - Response builder (framework-specific but implements our trait)
///
/// # Returns
///
/// Returns either a successful response with token or an error message.
///
/// # Example
///
/// ```ignore
/// // In an Axum route:
/// pub async fn axum_verify_2fa(
///     State(scheme): State<JwtScheme>,
///     Json(req): Json<Verify2FaRequest>,
/// ) -> Result<Response, Verify2FaError> {
///     let data = Verify2FaData {
///         email: req.email.expose_secret().clone(),
///         login_attempt_id: req.login_attempt_id,
///         two_factor_code: req.two_factor_code,
///     };
///     let builder = response_builder();
///     handle_verify_2fa(&scheme, data, builder)
///         .await
///         .map_err(|e| Verify2FaError::from(e))
/// }
/// ```
pub async fn handle_verify_2fa<S, B>(
    scheme: &S,
    data: Verify2FaData,
    builder: B,
) -> Result<B::Response, String>
where
    S: HttpAuthenticationScheme + SupportsTwoFactor,
    B: AuthResponseBuilder,
{
    // Parse email
    let email = Email::try_from(secrecy::Secret::new(data.email))
        .map_err(|e| format!("Invalid email: {}", e))?;

    // Parse login attempt ID
    let attempt_id = TwoFaAttemptId::parse(&data.login_attempt_id)
        .map_err(|e| format!("Invalid attempt ID: {}", e))?;

    // Parse 2FA code
    let code =
        TwoFaCode::parse(data.two_factor_code).map_err(|e| format!("Invalid 2FA code: {}", e))?;

    // Verify the 2FA code and get token (domain logic)
    let token = scheme
        .verify_2fa(email, attempt_id, code)
        .await
        .map_err(|e| format!("2FA verification failed: {}", e))?;

    // Create the 2FA success response
    Ok(scheme.create_2fa_response(builder, token))
}
