//! Framework-agnostic token verification handler.

use tempered_core::AuthResponseBuilder;

/// Framework-agnostic token verification handler.
///
/// This handler assumes the token has already been validated by middleware.
/// It simply returns a success response to indicate the token is valid.
///
/// # Type Parameters
/// * `B` - Response builder for the framework being used
///
/// # Arguments
/// * `builder` - HTTP response builder
///
/// # Returns
/// A success response indicating the token is valid
pub async fn handle_verify_token<B>(builder: B) -> Result<B::Response, String>
where
    B: AuthResponseBuilder,
{
    // If we reached this handler, the middleware already validated the token
    // Just return success
    Ok(builder
        .status(200)
        .json_body(serde_json::json!({"status": "valid"}))
        .build())
}
