//! Framework-neutral error classification.
//!
//! Core stays free of any transport crate (`http`, gRPC, …). Errors classify
//! themselves into a small protocol-neutral [`ErrorCategory`]; each delivery
//! adapter maps that category to its own status representation (the axum
//! adapter maps it to an `http::StatusCode`, for example).

/// A protocol-neutral classification of an error.
///
/// Delivery adapters map this to a concrete status. The suggested HTTP mapping
/// is noted on each variant, but nothing here depends on HTTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// Missing or invalid authentication credentials (HTTP 401).
    Unauthorized,
    /// Invalid input, malformed data, or validation failure (HTTP 400).
    BadRequest,
    /// Conflict with existing state, e.g. a duplicate (HTTP 409).
    Conflict,
    /// The target resource does not exist (HTTP 404).
    NotFound,
    /// A rate or attempt limit was exceeded (HTTP 429).
    TooManyRequests,
    /// An upstream/provider dependency failed (HTTP 502).
    BadGateway,
    /// An unexpected server-side failure (HTTP 500).
    Internal,
}

/// Convert an error into a protocol-neutral category and a client-safe message.
///
/// Implementors decide the category and craft a message that is clear and
/// actionable without leaking internals or sensitive data (log the internals
/// separately). The delivery adapter turns the category into a concrete status.
///
/// # Example
///
/// ```ignore
/// impl ClassifyError for UserError {
///     fn classify(self) -> (ErrorCategory, String) {
///         match self {
///             UserError::InvalidEmail(msg) => (ErrorCategory::BadRequest, msg),
///             UserError::NotFound => (ErrorCategory::NotFound, "User not found".into()),
///             UserError::AlreadyExists => (ErrorCategory::Conflict, "User already exists".into()),
///         }
///     }
/// }
/// ```
pub trait ClassifyError {
    /// Classify this error and produce a client-safe message.
    fn classify(self) -> (ErrorCategory, String);
}
