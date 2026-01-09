//! Framework-agnostic handler for verifying elevated tokens.
//!
//! Elevated tokens have stricter validation requirements and shorter lifetimes
//! than regular authentication tokens.

use tempered_core::{ResponseBuilder, HttpResponseBuilderExt};

/// Framework-agnostic elevated token verification handler.
///
/// This handler assumes the elevated token has already been validated by middleware.
/// It simply returns a success response to indicate the elevated token is valid.
///
/// # Type Parameters
/// * `B` - Response builder for the framework being used
///
/// # Arguments
/// * `builder` - HTTP response builder
///
/// # Returns
/// A success response indicating the elevated token is valid
pub async fn handle_verify_elevated_token<B>(builder: B) -> Result<B::Response, String>
where
    B: ResponseBuilder,
{
    // If we reached this handler, the middleware already validated the elevated token
    // Just return success
    Ok(builder
        .status(200)
        .json_body(serde_json::json!({"status": "valid"}))
        .build().map_err(|e| e.message)?)
}
