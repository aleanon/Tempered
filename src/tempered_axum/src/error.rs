//! HTTP status mapping for the core's neutral [`ErrorCategory`].
//!
//! `tempered_core` classifies errors into a protocol-neutral [`ErrorCategory`];
//! this axum delivery layer turns that into a concrete [`http::StatusCode`]. A
//! second framework adapter would provide its own mapping here without touching
//! core or the schemes.

use http::StatusCode;
use tempered_core::{ClassifyError, ErrorCategory};

/// Map a neutral [`ErrorCategory`] to its HTTP status code.
pub fn status_code(category: ErrorCategory) -> StatusCode {
    match category {
        ErrorCategory::Unauthorized => StatusCode::UNAUTHORIZED,
        ErrorCategory::BadRequest => StatusCode::BAD_REQUEST,
        ErrorCategory::Conflict => StatusCode::CONFLICT,
        ErrorCategory::NotFound => StatusCode::NOT_FOUND,
        ErrorCategory::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
        ErrorCategory::BadGateway => StatusCode::BAD_GATEWAY,
        ErrorCategory::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Resolve a classifiable error to an HTTP status code + client-safe message.
///
/// Blanket-implemented for every [`ClassifyError`], so routes and middleware
/// call `err.into_status_message()` exactly as before — the only change is that
/// the HTTP status now comes from the neutral category the core assigned, not
/// from an `http` type baked into the core.
pub trait IntoStatusMessage: ClassifyError + Sized {
    fn into_status_message(self) -> (StatusCode, String) {
        let (category, message) = self.classify();
        (status_code(category), message)
    }
}

impl<T: ClassifyError> IntoStatusMessage for T {}
