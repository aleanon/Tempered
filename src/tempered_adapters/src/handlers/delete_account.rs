//! Framework-agnostic account deletion handler.
//!
//! Account deletion is a sensitive operation that typically requires elevated authentication.

use tempered_application::DeleteAccountUseCase;
use tempered_core::{AuthResponseBuilder, Email, UserStore};

/// Framework-agnostic account deletion handler.
///
/// Deletes a user's account using the application layer use case.
/// This is a sensitive operation - routes should verify elevated authentication before calling this.
///
/// # Type Parameters
/// * `U` - User store for deleting the account
/// * `B` - Response builder for the framework being used
///
/// # Arguments
/// * `user_store` - The user store for deleting the account
/// * `email` - User's email (extracted from authenticated/elevated token by the route)
/// * `builder` - HTTP response builder
///
/// # Returns
/// Either an HTTP success response, or an error message
pub async fn handle_delete_account<U, B>(
    user_store: U,
    email: Email,
    builder: B,
) -> Result<B::Response, String>
where
    U: UserStore,
    B: AuthResponseBuilder,
{
    // Use the application layer use case
    let use_case = DeleteAccountUseCase::new(user_store);
    use_case
        .execute(email)
        .await
        .map_err(|e| format!("Failed to delete account: {}", e))?;

    // Return success response
    Ok(builder
        .status(200)
        .json_body(serde_json::json!({
            "status": "success",
            "message": "Account deleted successfully"
        }))
        .build())
}
