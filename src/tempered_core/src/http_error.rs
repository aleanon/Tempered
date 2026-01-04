//! Framework-agnostic HTTP error mapping.
//!
//! This module provides a trait for converting domain errors into HTTP status codes
//! and error messages, allowing error handling to remain framework-agnostic.

use http::StatusCode;

/// Trait for converting errors into HTTP status codes and error messages.
///
/// This trait provides a framework-agnostic way to map domain/application errors
/// to HTTP responses. Different web frameworks can then use this information to
/// construct their framework-specific error responses.
///
/// # Design Rationale
///
/// By separating the mapping logic (status code + message) from the response
/// construction, we keep the core domain logic framework-agnostic while still
/// providing guidance on how errors should be presented over HTTP.
///
/// # Example
///
/// ```ignore
/// impl IntoStatusMessage for UserError {
///     fn into_status_message(self) -> (StatusCode, String) {
///         match self {
///             UserError::InvalidEmail(msg) => (StatusCode::BAD_REQUEST, msg),
///             UserError::NotFound => (StatusCode::NOT_FOUND, "User not found".to_string()),
///             UserError::AlreadyExists => (StatusCode::CONFLICT, "User already exists".to_string()),
///         }
///     }
/// }
///
/// // In an Axum handler:
/// let (status, message) = error.into_status_message();
/// (status, Json(json!({ "error": message }))).into_response()
/// ```
pub trait IntoStatusMessage {
    /// Convert this error into an HTTP status code and error message.
    ///
    /// # Returns
    ///
    /// A tuple of:
    /// - `StatusCode`: The appropriate HTTP status code for this error
    /// - `String`: A human-readable error message suitable for client consumption
    ///
    /// # Guidelines
    ///
    /// - **400 Bad Request**: Invalid input, malformed data, validation failures
    /// - **401 Unauthorized**: Missing or invalid authentication credentials
    /// - **403 Forbidden**: Valid auth but insufficient permissions
    /// - **404 Not Found**: Resource doesn't exist
    /// - **409 Conflict**: Resource already exists, constraint violation
    /// - **422 Unprocessable Entity**: Valid syntax but semantic errors
    /// - **500 Internal Server Error**: Unexpected errors, database failures
    ///
    /// Error messages should be:
    /// - Clear and actionable for API consumers
    /// - Not expose internal implementation details
    /// - Not leak sensitive information
    fn into_status_message(self) -> (StatusCode, String);
}
