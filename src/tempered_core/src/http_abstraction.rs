//! Zero-cost HTTP abstraction traits for authentication library.
//!
//! This module defines trait-based HTTP abstractions that frameworks implement directly
//! on their own types (via newtype wrappers), avoiding any allocation or copying overhead.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────┐
//! │  tempered_core: Defines HTTP traits      │
//! └──────────────┬───────────────────────────┘
//!                │
//!                ▼
//! ┌──────────────────────────────────────────┐
//! │  tempered_axum: Newtype wrappers         │
//! │  struct AxumRequest(axum::Request)       │
//! │  impl AuthRequest for AxumRequest { }    │  ← Zero cost!
//! └──────────────┬───────────────────────────┘
//!                │
//!                ▼
//! ┌──────────────────────────────────────────┐
//! │  Authentication logic uses AuthRequest   │
//! │  trait methods (generic over framework)  │
//! └──────────────────────────────────────────┘
//! ```
//!
//! # Orphan Rule Solution
//!
//! Framework-specific crates create zero-cost newtype wrappers:
//! ```ignore
//! // In tempered-axum crate
//! pub struct AxumRequest(pub axum::Request<Body>);
//!
//! impl tempered_core::AuthRequest for AxumRequest {
//!     fn header(&self, name: &str) -> Option<&str> {
//!         self.0.headers().get(name)?.to_str().ok()
//!     }
//!     // ... just delegates to inner type
//! }
//!
//! // Auth logic works with any framework
//! fn extract_token<R: AuthRequest>(req: &R) -> Option<String> {
//!     req.cookie("auth_token").map(String::from)
//! }
//! ```

/// Trait for HTTP requests that can be used for authentication.
///
/// Web frameworks implement this trait on newtype wrappers of their request types
/// to enable authentication without any allocation or copying overhead.
///
/// # Implementation Notes
///
/// - Return `&str` references directly from the framework's data structures
/// - No allocation or copying required
/// - Case-insensitive header lookup should be handled by implementor
///
/// # Example
///
/// ```ignore
/// // In tempered-axum crate
/// pub struct AxumRequest(pub axum::http::Request<axum::body::Body>);
///
/// impl AuthRequest for AxumRequest {
///     fn header(&self, name: &str) -> Option<&str> {
///         self.0.headers().get(name)?.to_str().ok()
///     }
///
///     fn cookie(&self, name: &str) -> Option<&str> {
///         // Parse Cookie header and find the named cookie
///         let cookie_header = self.header("cookie")?;
///         parse_cookie(cookie_header, name)
///     }
///
///     fn method(&self) -> &str {
///         self.0.method().as_str()
///     }
///
///     fn path(&self) -> &str {
///         self.0.uri().path()
///     }
/// }
/// ```
pub trait AuthRequest {
    /// Get a header value by name.
    ///
    /// Header lookup should be case-insensitive (per HTTP spec).
    /// Returns `None` if the header doesn't exist or isn't valid UTF-8.
    fn header(&self, name: &str) -> Option<&str>;

    /// Get a cookie value by name.
    ///
    /// Parses the Cookie header and extracts the named cookie.
    /// Returns `None` if the cookie doesn't exist.
    fn cookie(&self, name: &str) -> Option<&str>;

    /// Get the HTTP method (GET, POST, etc.)
    fn method(&self) -> &str;

    /// Get the request path
    fn path(&self) -> &str;
}

/// Protocol-agnostic trait for building responses.
///
/// This trait can be implemented for any protocol:
/// - HTTP (headers, cookies, status codes)
/// - gRPC (metadata, status codes)
/// - WebSocket (message types)
/// - GraphQL (response structure)
///
/// # Design
///
/// This follows the builder pattern, allowing method chaining:
/// ```ignore
/// builder
///     .status(200)
///     .metadata("content-type", "application/json")
///     .body(json!({"message": "success"}))
///     .build()
/// ```
///
/// # HTTP Example
///
/// ```ignore
/// // In tempered-adapters crate
/// pub struct HttpResponseBuilder { ... }
///
/// impl ResponseBuilder for HttpResponseBuilder {
///     type Response = http::Response<String>;
///
///     fn status(mut self, code: u16) -> Self {
///         self.status_code = code;
///         self
///     }
///
///     fn metadata(mut self, key: &str, value: &str) -> Self {
///         if key.starts_with("cookie:") {
///             self.cookies.push(...);
///         } else {
///             self.headers.push((key, value));
///         }
///         self
///     }
///
///     fn body<T: Serialize>(mut self, body: T) -> Self {
///         self.body = Some(serde_json::to_value(body).unwrap());
///         self
///     }
///
///     fn build(self) -> Self::Response {
///         // Build http::Response
///     }
/// }
/// ```
///
/// # gRPC Example
///
/// ```ignore
/// pub struct GrpcResponseBuilder { ... }
///
/// impl ResponseBuilder for GrpcResponseBuilder {
///     type Response = tonic::Response<ProtoMessage>;
///
///     fn status(self, code: u16) -> Self {
///         // Map to gRPC status codes
///     }
///
///     fn metadata(self, key: &str, value: &str) -> Self {
///         // Add to gRPC metadata
///     }
///
///     fn body<T: Serialize>(self, body: T) -> Self {
///         // Convert to protobuf
///     }
///
///     fn build(self) -> Self::Response {
///         // Build tonic::Response
///     }
/// }
/// ```
/// Error type for response building operations
#[derive(Debug, Clone)]
pub struct ResponseBuilderError {
    pub message: String,
}

impl std::fmt::Display for ResponseBuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Response builder error: {}", self.message)
    }
}

impl std::error::Error for ResponseBuilderError {}

impl ResponseBuilderError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

pub trait ResponseBuilder: Sized {
    /// The final response type produced by this builder
    type Response;

    /// Set the response status/result code
    ///
    /// For HTTP: 200, 404, 500, etc.
    /// For gRPC: maps to Status codes
    /// For WebSocket: success/error indicators
    ///
    /// This method is infallible - invalid status codes are stored and validated during `build()`.
    fn status(self, code: u16) -> Self;

    /// Add metadata (protocol-specific)
    ///
    /// For HTTP: headers and cookies (use "cookie:" prefix for cookies)
    /// For gRPC: metadata entries
    /// For WebSocket: custom message headers
    ///
    /// This method is infallible - invalid keys/values are stored and validated during `build()`.
    fn metadata(self, key: &str, value: &str) -> Self;

    /// Set response body from serializable data
    ///
    /// For HTTP: JSON body
    /// For gRPC: protobuf message
    /// For WebSocket: message payload
    ///
    /// This method is infallible - the body is stored and serialized during `build()`.
    fn body<T: serde::Serialize>(self, body: T) -> Self;

    /// Build the final response
    ///
    /// This consumes the builder and produces the protocol's response type.
    ///
    /// This is the only fallible operation - it validates all collected data,
    /// performs serialization, and constructs the final response.
    ///
    /// Returns an error if:
    /// - The status code is invalid for this protocol
    /// - Metadata keys/values are invalid
    /// - Serialization fails
    /// - Required fields are missing
    fn build(self) -> Result<Self::Response, ResponseBuilderError>;
}

/// Type alias for backward compatibility
///
/// This allows existing code using `AuthResponseBuilder` to continue working
/// while we transition to the more generic `ResponseBuilder` name.
#[deprecated(since = "0.1.0", note = "Use ResponseBuilder instead")]
pub trait AuthResponseBuilder: ResponseBuilder {}

/// HTTP-specific extension methods for ResponseBuilder.
///
/// These provide HTTP-specific conveniences like headers, cookies, and JSON bodies.
pub trait HttpResponseBuilderExt: ResponseBuilder {
    /// Add an HTTP header
    fn header(self, name: &str, value: &str) -> Self {
        self.metadata(name, value)
    }

    /// Add a Set-Cookie header
    ///
    /// The cookie_value should be a complete cookie string like:
    /// `"auth=token; HttpOnly; Secure; SameSite=Lax; Max-Age=3600"`
    fn cookie(self, cookie_value: &str) -> Self {
        self.metadata("set-cookie", cookie_value)
    }

    /// Set a JSON body with Content-Type header
    ///
    /// This is a convenience method that:
    /// 1. Sets Content-Type: application/json
    /// 2. Serializes the JSON value to a string
    /// 3. Sets it as the response body
    fn json_body(self, body: serde_json::Value) -> Self {
        self.metadata("content-type", "application/json").body(body)
    }
}

// Blanket implementation for all ResponseBuilder types
impl<T: ResponseBuilder> HttpResponseBuilderExt for T {}

/// Helper methods for creating common authentication responses.
///
/// This trait provides convenience methods for common response types.
/// It's automatically implemented for all types that implement `ResponseBuilder`.
pub trait AuthResponseHelpers: ResponseBuilder {
    /// Create a 200 OK JSON response
    fn ok_json(self, body: serde_json::Value) -> Result<Self::Response, ResponseBuilderError> {
        self.status(200).json_body(body).build()
    }

    /// Create a 401 Unauthorized response
    fn unauthorized(self, message: &str) -> Result<Self::Response, ResponseBuilderError> {
        self.status(401)
            .json_body(serde_json::json!({ "error": message }))
            .build()
    }

    /// Create a 400 Bad Request response
    fn bad_request(self, message: &str) -> Result<Self::Response, ResponseBuilderError> {
        self.status(400)
            .json_body(serde_json::json!({ "error": message }))
            .build()
    }

    /// Create a 500 Internal Server Error response
    fn internal_error(self, message: &str) -> Result<Self::Response, ResponseBuilderError> {
        self.status(500)
            .json_body(serde_json::json!({ "error": message }))
            .build()
    }

    /// Create a 206 Partial Content response (used for 2FA required)
    fn partial_content(
        self,
        body: serde_json::Value,
    ) -> Result<Self::Response, ResponseBuilderError> {
        self.status(206).json_body(body).build()
    }
}

// Blanket implementation for all ResponseBuilder types
impl<T: ResponseBuilder> AuthResponseHelpers for T {}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock request for testing
    struct MockRequest {
        headers: std::collections::HashMap<String, String>,
        cookies: std::collections::HashMap<String, String>,
        method: String,
        path: String,
    }

    impl AuthRequest for MockRequest {
        fn header(&self, name: &str) -> Option<&str> {
            let name_lower = name.to_lowercase();
            self.headers
                .iter()
                .find(|(k, _)| k.to_lowercase() == name_lower)
                .map(|(_, v)| v.as_str())
        }

        fn cookie(&self, name: &str) -> Option<&str> {
            self.cookies.get(name).map(|s| s.as_str())
        }

        fn method(&self) -> &str {
            &self.method
        }

        fn path(&self) -> &str {
            &self.path
        }
    }

    #[test]
    fn test_auth_request_trait() {
        let mut req = MockRequest {
            headers: std::collections::HashMap::new(),
            cookies: std::collections::HashMap::new(),
            method: "POST".to_string(),
            path: "/login".to_string(),
        };

        req.headers
            .insert("Content-Type".to_string(), "application/json".to_string());
        req.cookies
            .insert("session".to_string(), "abc123".to_string());

        assert_eq!(req.method(), "POST");
        assert_eq!(req.path(), "/login");
        assert_eq!(req.header("content-type"), Some("application/json")); // case-insensitive
        assert_eq!(req.cookie("session"), Some("abc123"));
    }
}
