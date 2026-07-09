//! Shared handler error wrapper.

use tempered_core::{ClassifyError, ErrorCategory, ResponseBuilderError};

/// A handler failure: either the scheme's own error (`E`) or a failure while
/// building the HTTP response.
///
/// Handlers that deliver a response through a [`ResponseBuilder`] used to
/// `.expect()` on the builder result, panicking the worker on what is really a
/// scheme/adapter bug. Wrapping the two lets handlers propagate the builder
/// error with `?` instead. A [`ResponseBuilderError`] therefore maps to `500`
/// (it means the scheme built an invalid response — a bug, not a client error),
/// while the scheme error keeps its own status mapping.
///
/// [`ResponseBuilder`]: tempered_core::ResponseBuilder
#[derive(Debug)]
pub enum HandlerError<E> {
    /// The scheme's domain/auth error.
    Auth(E),
    /// The framework's response builder failed (a bug in the scheme's response
    /// construction).
    Response(ResponseBuilderError),
}

impl<E> From<ResponseBuilderError> for HandlerError<E> {
    fn from(e: ResponseBuilderError) -> Self {
        HandlerError::Response(e)
    }
}

impl<E: ClassifyError> ClassifyError for HandlerError<E> {
    fn classify(self) -> (ErrorCategory, String) {
        match self {
            HandlerError::Auth(e) => e.classify(),
            HandlerError::Response(e) => {
                tracing::error!(error = %e, "response builder failed (scheme bug)");
                (
                    ErrorCategory::Internal,
                    "Internal error".to_string(),
                )
            }
        }
    }
}
