//! HTTP-specific response builder using the `http` crate.
//!
//! This module provides `HttpResponseBuilder`, an implementation of the protocol-agnostic
//! `ResponseBuilder` trait for HTTP responses using the standard `http` crate.

use http::{
    Response, StatusCode,
    header::{HeaderName, HeaderValue, SET_COOKIE},
};
use serde::Serialize;
use tempered_core::{ResponseBuilder, ResponseBuilderError};

/// HTTP-specific response builder using the `http` crate.
///
/// This builder constructs `http::Response<String>` responses with:
/// - HTTP status codes
/// - Headers and cookies
/// - JSON body
///
/// # Example
///
/// ```ignore
/// use tempered_adapters::http::HttpResponseBuilder;
/// use tempered_core::ResponseBuilder;
///
/// let response = HttpResponseBuilder::new()
///     .status(200)
///     .header("content-type", "application/json")
///     .cookie("session=abc123; HttpOnly; Secure")
///     .body(serde_json::json!({"message": "success"}))
///     .build();
/// ```
#[derive(Default)]
pub struct HttpResponseBuilder {
    status: u16,
    headers: Vec<(String, String)>,
    cookies: Vec<String>,
    body: Option<serde_json::Value>,
}

impl HttpResponseBuilder {
    /// Create a new HTTP response builder with default values.
    pub fn new() -> Self {
        Self {
            status: 200,
            headers: vec![],
            cookies: vec![],
            body: None,
        }
    }

    /// HTTP-specific convenience method for adding cookies.
    ///
    /// This is a helper that provides better ergonomics for HTTP cookie handling.
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.cookie("session=abc; HttpOnly; Secure; SameSite=Lax; Path=/")
    /// ```
    pub fn cookie(mut self, cookie: &str) -> Self {
        self.cookies.push(cookie.to_string());
        self
    }

    /// HTTP-specific convenience method for adding headers.
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.header("content-type", "application/json")
    /// ```
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// HTTP-specific convenience method for JSON body.
    ///
    /// Sets the content-type to application/json automatically.
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.json_body(serde_json::json!({"status": "success"}))
    /// ```
    pub fn json_body(self, body: serde_json::Value) -> Self {
        self.body(body)
    }
}

impl ResponseBuilder for HttpResponseBuilder {
    type Response = Response<String>;

    fn status(mut self, code: u16) -> Self {
        self.status = code;
        self
    }

    fn metadata(mut self, key: &str, value: &str) -> Self {
        // Convention: "cookie:" prefix for cookies, otherwise treat as header
        if key.starts_with("cookie:") {
            let cookie_name = &key[7..];
            if value.is_empty() {
                // Clear cookie by setting Max-Age=0
                self.cookies.push(format!(
                    "{}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
                    cookie_name
                ));
            } else {
                // Set cookie with value
                self.cookies.push(format!("{}={}", cookie_name, value));
            }
        } else {
            // Regular header
            self.headers.push((key.to_string(), value.to_string()));
        }
        self
    }

    fn body<T: Serialize>(mut self, body: T) -> Self {
        // Store the value - serialization happens in build()
        match serde_json::to_value(body) {
            Ok(value) => {
                self.body = Some(value);
                self
            }
            Err(_) => {
                // Store an error marker - will be caught in build()
                self.body = None;
                self
            }
        }
    }

    fn build(self) -> Result<Self::Response, ResponseBuilderError> {
        // Validate and serialize body
        let body_str = if let Some(body_value) = self.body {
            serde_json::to_string(&body_value).map_err(|e| {
                ResponseBuilderError::new(format!("Failed to serialize JSON body: {}", e))
            })?
        } else {
            "{}".to_string()
        };

        // Validate status code
        let status = StatusCode::from_u16(self.status).map_err(|_| {
            ResponseBuilderError::new(format!("Invalid HTTP status code: {}", self.status))
        })?;

        let mut response = Response::builder().status(status);

        // Add Content-Type for JSON
        response = response.header("Content-Type", "application/json");

        // Add custom headers
        for (key, value) in self.headers {
            let header_name = HeaderName::from_bytes(key.as_bytes()).map_err(|e| {
                ResponseBuilderError::new(format!("Invalid header name '{}': {}", key, e))
            })?;
            let header_value = HeaderValue::from_str(&value).map_err(|e| {
                ResponseBuilderError::new(format!("Invalid header value for '{}': {}", key, e))
            })?;
            response = response.header(header_name, header_value);
        }

        // Add cookies as Set-Cookie headers
        for cookie in self.cookies {
            let cookie_value = HeaderValue::from_str(&cookie)
                .map_err(|e| ResponseBuilderError::new(format!("Invalid cookie value: {}", e)))?;
            response = response.header(SET_COOKIE, cookie_value);
        }

        response
            .body(body_str)
            .map_err(|e| ResponseBuilderError::new(format!("Failed to build HTTP response: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_response() {
        let response = HttpResponseBuilder::new()
            .status(200)
            .body(serde_json::json!({"message": "hello"}))
            .build()
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), r#"{"message":"hello"}"#);
    }

    #[test]
    fn test_with_headers() {
        let response = HttpResponseBuilder::new()
            .status(200)
            .header("X-Custom", "value")
            .body(serde_json::json!({}))
            .build()
            .unwrap();

        assert_eq!(response.headers().get("X-Custom").unwrap(), "value");
    }

    #[test]
    fn test_with_cookies() {
        let response = HttpResponseBuilder::new()
            .status(200)
            .cookie("session=abc123; HttpOnly")
            .body(serde_json::json!({}))
            .build()
            .unwrap();

        let cookies: Vec<_> = response.headers().get_all(SET_COOKIE).iter().collect();

        assert_eq!(cookies.len(), 1);
        assert!(cookies[0].to_str().unwrap().contains("session=abc123"));
    }

    #[test]
    fn test_metadata_for_cookies() {
        let response = HttpResponseBuilder::new()
            .status(200)
            .metadata("cookie:session", "abc123")
            .body(serde_json::json!({}))
            .build()
            .unwrap();

        let cookies: Vec<_> = response.headers().get_all(SET_COOKIE).iter().collect();

        assert_eq!(cookies.len(), 1);
        assert!(cookies[0].to_str().unwrap().contains("session=abc123"));
    }

    #[test]
    fn test_clear_cookie() {
        let response = HttpResponseBuilder::new()
            .status(200)
            .metadata("cookie:session", "")
            .body(serde_json::json!({}))
            .build()
            .unwrap();

        let cookies: Vec<_> = response.headers().get_all(SET_COOKIE).iter().collect();

        assert_eq!(cookies.len(), 1);
        assert!(cookies[0].to_str().unwrap().contains("Max-Age=0"));
    }

    #[test]
    fn test_invalid_status_code() {
        // The http crate accepts status codes 100-999
        // Use 99 (below minimum) and 1000 (above maximum) to test error handling
        let result_too_low = HttpResponseBuilder::new()
            .status(99) // Below minimum valid HTTP status (100)
            .body(serde_json::json!({}))
            .build();

        assert!(result_too_low.is_err());
        assert!(
            result_too_low
                .unwrap_err()
                .message
                .contains("Invalid HTTP status code")
        );

        let result_too_high = HttpResponseBuilder::new()
            .status(1000) // Above maximum valid HTTP status (999)
            .body(serde_json::json!({}))
            .build();

        assert!(result_too_high.is_err());
        assert!(
            result_too_high
                .unwrap_err()
                .message
                .contains("Invalid HTTP status code")
        );
    }
}
