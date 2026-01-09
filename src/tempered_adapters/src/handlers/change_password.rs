//! Framework-agnostic password change handler.
//!
//! Password changes are sensitive operations that typically require elevated authentication.

use tempered_core::{ResponseBuilder, HttpResponseBuilderExt, Email, Password, SupportsPasswordChange};

/// Framework-agnostic password change handler.
///
/// Changes a user's password using the authentication scheme.
/// This is a sensitive operation - routes should verify elevated authentication before calling this.
///
/// # Type Parameters
/// * `S` - Authentication scheme that supports password changes
/// * `B` - Response builder for the framework being used
///
/// # Arguments
/// * `scheme` - The authentication scheme
/// * `email` - User's email (extracted from authenticated/elevated token by the route)
/// * `new_password` - The new password
/// * `builder` - HTTP response builder
///
/// # Returns
/// Either an HTTP success response, or an error message
pub async fn handle_change_password<S, B>(
    scheme: S,
    email: Email,
    new_password: Password,
    builder: B,
) -> Result<B::Response, String>
where
    S: SupportsPasswordChange,
    B: ResponseBuilder,
{
    // Use the scheme's password change capability
    scheme
        .change_password(email, new_password)
        .await
        .map_err(|e| format!("Failed to change password: {}", e))?;

    // Return success response
    Ok(builder
        .status(200)
        .json_body(serde_json::json!({
            "status": "success",
            "message": "Password changed successfully"
        }))
        .build().map_err(|e| e.message)?)
}
