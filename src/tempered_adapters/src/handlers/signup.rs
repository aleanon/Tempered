//! Framework-agnostic signup handler.

use tempered_core::{
    Email, HttpResponseBuilderExt, Password, ResponseBuilder, SupportsRegistration,
};

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
/// Either an HTTP success response, or the registration error
pub async fn handle_signup<S, B>(
    scheme: &S,
    data: SignupData<S::RegistrationData>,
    builder: B,
) -> Result<B::Response, S::RegistrationError>
where
    S: SupportsRegistration,
    B: ResponseBuilder,
{
    // Register the user
    scheme
        .register(data.email, data.password, data.registration_data)
        .await?;

    // Return success response
    builder
        .status(201)
        .json_body(serde_json::json!({
            "status": "success",
            "message": "User created successfully"
        }))
        .build()
        .map_err(|_e| {
            // ResponseBuilder errors are programming errors (invalid status codes, etc.)
            // This should never happen as we're using valid status 201
            panic!("ResponseBuilder error in signup handler - this is a bug")
        })
}
