//! Framework-agnostic password change handler.
//!
//! Password changes are sensitive operations that typically require elevated authentication.

use tempered_application::ChangePasswordUseCase;
use tempered_core::{AuthResponseBuilder, Email, Password, UserStore};

/// Framework-agnostic password change handler.
///
/// Changes a user's password using the application layer use case.
/// This is a sensitive operation - routes should verify elevated authentication before calling this.
///
/// # Type Parameters
/// * `U` - User store for persisting the password change
/// * `B` - Response builder for the framework being used
///
/// # Arguments
/// * `user_store` - The user store for updating the password
/// * `email` - User's email (extracted from authenticated/elevated token by the route)
/// * `new_password` - The new password
/// * `builder` - HTTP response builder
///
/// # Returns
/// Either an HTTP success response, or an error message
pub async fn handle_change_password<U, B>(
    user_store: U,
    email: Email,
    new_password: Password,
    builder: B,
) -> Result<B::Response, String>
where
    U: UserStore,
    B: AuthResponseBuilder,
{
    // Use the application layer use case
    let use_case = ChangePasswordUseCase::new(user_store);
    use_case
        .execute(email, new_password)
        .await
        .map_err(|e| format!("Failed to change password: {}", e))?;

    // Return success response
    Ok(builder
        .status(200)
        .json_body(serde_json::json!({
            "status": "success",
            "message": "Password changed successfully"
        }))
        .build())
}
