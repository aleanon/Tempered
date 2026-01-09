//! Framework-agnostic account deletion handler.
//!
//! Account deletion is a sensitive operation that typically requires elevated authentication.

use tempered_core::{ResponseBuilder, HttpResponseBuilderExt, Email, SupportsAccountDeletion};

/// Framework-agnostic account deletion handler.
///
/// Deletes a user's account using the authentication scheme.
/// This is a sensitive operation - routes should verify elevated authentication before calling this.
///
/// # Type Parameters
/// * `S` - Authentication scheme that supports account deletion
/// * `B` - Response builder for the framework being used
///
/// # Arguments
/// * `scheme` - The authentication scheme
/// * `email` - User's email (extracted from authenticated/elevated token by the route)
/// * `builder` - HTTP response builder
///
/// # Returns
/// Either an HTTP success response, or an error message
pub async fn handle_delete_account<S, B>(
    scheme: S,
    email: Email,
    builder: B,
) -> Result<B::Response, String>
where
    S: SupportsAccountDeletion,
    B: ResponseBuilder,
{
    // Use the scheme's account deletion capability
    scheme
        .delete_account(email)
        .await
        .map_err(|e| format!("Failed to delete account: {}", e))?;

    // Return success response
    Ok(builder
        .status(200)
        .json_body(serde_json::json!({
            "status": "success",
            "message": "Account deleted successfully"
        }))
        .build().map_err(|e| e.message)?)
}
