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
    /// Authenticated, but this is not allowed for this account (HTTP 403).
    Forbidden,
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

/// The cause of an unexpected failure in a store or client: what went
/// wrong, and when there was one, the original error as its
/// [`source`](std::error::Error::source), so a caller can tell a
/// connection failure from a constraint violation by downcasting it.
///
/// Cheap to clone; compares by message.
#[derive(Clone)]
pub struct Failure {
    message: String,
    source: Option<std::sync::Arc<dyn std::error::Error + Send + Sync>>,
}

impl Failure {
    /// A failure caused by `error`, kept as the source.
    pub fn new(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self {
            message: error.to_string(),
            source: Some(std::sync::Arc::new(error)),
        }
    }

    /// A failure with a message and no underlying error.
    pub fn message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// The underlying error as `E`, if it is one.
    pub fn downcast_ref<E: std::error::Error + 'static>(&self) -> Option<&E> {
        self.source.as_deref().and_then(|e| e.downcast_ref::<E>())
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::fmt::Debug for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Failure").field(&self.message).finish()
    }
}

impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

impl PartialEq for Failure {
    fn eq(&self, other: &Self) -> bool {
        self.message == other.message
    }
}

impl Eq for Failure {}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self::message(message)
    }
}

impl From<&str> for Failure {
    fn from(message: &str) -> Self {
        Self::message(message)
    }
}
