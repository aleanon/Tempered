//! HTTP status mapping for the core's neutral [`ErrorCategory`].
//!
//! `tempered_core` classifies errors into a protocol-neutral [`ErrorCategory`];
//! the route table (`tempered_adapters::endpoints`) turns that into an
//! [`http::StatusCode`]. This re-exposes the mapping for the app's own axum
//! handlers.

use http::StatusCode;
use tempered_core::{ClassifyError, ErrorCategory};

/// Map a neutral [`ErrorCategory`] to its HTTP status code (the mapping
/// the route table uses, so the app's code and the library agree).
pub fn status_code(category: ErrorCategory) -> StatusCode {
    tempered_adapters::endpoints::status_for(category)
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
