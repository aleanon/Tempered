//! Axum framework adapters for zero-cost HTTP authentication.
//!
//! This module implements `AuthRequest` and `AuthResponseBuilder` for Axum's types
//! using newtype wrappers to avoid the orphan rule, while maintaining zero runtime cost.
//!
//! # Architecture
//!
//! The traits are defined in `tempered_core`, and we implement them here using
//! newtype wrappers:
//!
//! ```text
//! ┌────────────────────────────────────────────┐
//! │  tempered_core::AuthRequest (trait)        │
//! └────────────────┬───────────────────────────┘
//!                  │
//!                  ▼
//! ┌────────────────────────────────────────────┐
//! │  AxumRequest(axum::Request)                │
//! │  impl AuthRequest for AxumRequest { }      │  ← Zero cost!
//! └────────────────────────────────────────────┘
//! ```
//!
//! The newtype wrappers are optimized away at compile time (repr(transparent)),
//! so there's zero runtime overhead.

use axum::body::Body;
use axum::extract::Request as AxumExtractRequest;
use axum::http::Response;
use tempered_core::{AuthRequest, AuthResponseBuilder};

/// Newtype wrapper around Axum's Request type.
///
/// This wrapper is zero-cost (repr(transparent)) and allows us to implement
/// `tempered_core::AuthRequest` without violating the orphan rule.
///
/// Note: Uses `axum::extract::Request` which is compatible with Axum's extractor system.
#[repr(transparent)]
pub struct AxumRequest(pub AxumExtractRequest);

impl From<AxumExtractRequest> for AxumRequest {
    fn from(req: AxumExtractRequest) -> Self {
        AxumRequest(req)
    }
}

impl From<AxumRequest> for AxumExtractRequest {
    fn from(wrapper: AxumRequest) -> Self {
        wrapper.0
    }
}

/// Implement AuthRequest for Axum's Request type (via newtype wrapper).
///
/// This is a zero-cost implementation - it just delegates to Axum's existing
/// methods without any allocation or copying.
impl AuthRequest for AxumRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.0.headers().get(name)?.to_str().ok()
    }

    fn cookie(&self, name: &str) -> Option<&str> {
        // Parse the Cookie header to extract the named cookie
        let cookie_header = self.header("cookie")?;

        // Simple cookie parsing - split by semicolon and find the named cookie
        for cookie_pair in cookie_header.split(';') {
            let parts: Vec<&str> = cookie_pair.trim().splitn(2, '=').collect();
            if parts.len() == 2 && parts[0] == name {
                return Some(parts[1]);
            }
        }

        None
    }

    fn method(&self) -> &str {
        self.0.method().as_str()
    }

    fn path(&self) -> &str {
        self.0.uri().path()
    }
}

/// Newtype wrapper around Axum's response builder.
///
/// This wrapper is zero-cost and allows us to implement `tempered_core::AuthResponseBuilder`
/// without violating the orphan rule.
pub struct AxumResponseBuilder {
    builder: axum::http::response::Builder,
    body: Option<String>,
}

impl AxumResponseBuilder {
    /// Create a new Axum response builder
    pub fn new() -> Self {
        Self {
            builder: Response::builder(),
            body: None,
        }
    }
}

impl Default for AxumResponseBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthResponseBuilder for AxumResponseBuilder {
    type Response = Response<Body>;

    fn status(mut self, code: u16) -> Self {
        self.builder = self.builder.status(code);
        self
    }

    fn header(mut self, name: &str, value: &str) -> Self {
        self.builder = self.builder.header(name, value);
        self
    }

    fn json_body(mut self, body: serde_json::Value) -> Self {
        self.builder = self.builder.header("content-type", "application/json");
        self.body = Some(body.to_string());
        self
    }

    fn build(self) -> Self::Response {
        let body = self.body.unwrap_or_default();
        self.builder
            .body(Body::from(body))
            .expect("Failed to build response")
    }
}

/// Helper function to create an Axum response builder
///
/// This is a convenience function for use in route handlers:
///
/// ```ignore
/// use tempered_adapters::http::axum_adapters::response_builder;
///
/// async fn login_handler() -> Response {
///     let builder = response_builder();
///     jwt_scheme.create_login_response(builder, outcome)
/// }
/// ```
pub fn response_builder() -> AxumResponseBuilder {
    AxumResponseBuilder::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;

    #[test]
    fn test_auth_request_implementation() {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/login")
            .header("content-type", "application/json")
            .header("cookie", "session=abc123; auth=xyz789")
            .body(Body::empty())
            .unwrap();

        let axum_req = AxumRequest(req);

        assert_eq!(axum_req.method(), "POST");
        assert_eq!(axum_req.path(), "/login");
        assert_eq!(axum_req.header("content-type"), Some("application/json"));
        assert_eq!(axum_req.cookie("session"), Some("abc123"));
        assert_eq!(axum_req.cookie("auth"), Some("xyz789"));
        assert_eq!(axum_req.cookie("nonexistent"), None);
    }

    #[test]
    fn test_response_builder() {
        let resp = response_builder()
            .status(200)
            .header("x-custom", "value")
            .json_body(serde_json::json!({"message": "success"}))
            .build();

        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("x-custom").and_then(|v| v.to_str().ok()),
            Some("value")
        );
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
    }

    #[test]
    fn test_newtype_is_zero_cost() {
        use std::mem::size_of;

        // Verify that AxumRequest has the same size as Request<Body>
        // This confirms it's truly zero-cost (repr(transparent))
        assert_eq!(size_of::<AxumRequest>(), size_of::<Request<Body>>());
    }
}
