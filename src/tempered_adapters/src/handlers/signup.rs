//! Framework-agnostic signup handler.

use tempered_core::{AuthResponseBuilder, Email, Password, SupportsRegistration};

/// Request data for user signup.
///
/// This is a framework-agnostic representation of the signup request.
pub struct SignupData<D> {
    pub email: Email,
    pub password: Password,
    pub registration_data: D,
}

/// Framework-agnostic signup handler.
///
/// Registers a new user account using the authentication scheme's registration capability.
///
/// # Type Parameters
/// * `S` - Authentication scheme that supports registration
/// * `B` - Response builder for the framework being used
///
/// # Arguments
/// * `scheme` - The authentication scheme instance
/// * `data` - Signup data (email, password, and scheme-specific registration data)
/// * `builder` - HTTP response builder
///
/// # Returns
/// Either an HTTP success response, or an error message
pub async fn handle_signup<S, B>(
    scheme: &S,
    data: SignupData<S::RegistrationData>,
    builder: B,
) -> Result<B::Response, String>
where
    S: SupportsRegistration,
    B: AuthResponseBuilder,
{
    // Register the user
    scheme
        .register(data.email, data.password, data.registration_data)
        .await
        .map_err(|e| format!("Registration failed: {}", e))?;

    // Return success response
    Ok(builder
        .status(201)
        .json_body(serde_json::json!({
            "status": "success",
            "message": "User created successfully"
        }))
        .build())
}
