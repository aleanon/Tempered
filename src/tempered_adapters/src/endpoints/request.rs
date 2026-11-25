//! The neutral request a framework adapter hands to [`Endpoints::handle`].
//!
//! [`Endpoints::handle`]: super::Endpoints::handle

use bytes::Bytes;
use http::{StatusCode, request::Parts};
use serde::de::DeserializeOwned;
use tempered_core::AuthRequest;

use super::{EndpointResponse, error_response};

/// A request, already read: head, body, and the path parameters the
/// framework's router matched (`provider` for the OAuth routes).
pub struct EndpointRequest {
    pub parts: Parts,
    pub body: Bytes,
    pub params: Vec<(String, String)>,
}

impl EndpointRequest {
    pub fn new(parts: Parts, body: Bytes, params: Vec<(String, String)>) -> Self {
        Self {
            parts,
            body,
            params,
        }
    }

    /// A matched path parameter.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// A query-string parameter, percent-decoded.
    pub fn query(&self, name: &str) -> Option<String> {
        let query = self.parts.uri.query()?;
        url::form_urlencoded::parse(query.as_bytes())
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.into_owned())
    }

    /// The request head, for code that reads headers and cookies through
    /// [`AuthRequest`].
    pub fn head(&self) -> RequestHead<'_> {
        RequestHead(&self.parts)
    }

    /// Parse the body as JSON, with the rules axum's `Json` extractor
    /// applies (tests pin the statuses):
    /// - `Content-Type` must be `application/json` (or `application/*+json`),
    ///   else `415`. A cross-site form cannot send that without a CORS
    ///   preflight, which is part of the CSRF defence.
    /// - Not JSON: `400`. JSON of the wrong shape: `422`.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, EndpointResponse> {
        if !has_json_content_type(&self.parts) {
            return Err(error_response(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Expected a request with `Content-Type: application/json`",
            ));
        }
        serde_json::from_slice(&self.body).map_err(|e| match e.classify() {
            serde_json::error::Category::Data => error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Request body has missing or invalid fields",
            ),
            _ => error_response(StatusCode::BAD_REQUEST, "Malformed request body"),
        })
    }
}

fn has_json_content_type(parts: &Parts) -> bool {
    let Some(value) = parts
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let mime = value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    mime == "application/json" || (mime.starts_with("application/") && mime.ends_with("+json"))
}

/// A request head as an [`AuthRequest`], for the handlers that read tokens
/// from headers or cookies.
pub struct RequestHead<'a>(pub &'a Parts);

impl AuthRequest for RequestHead<'_> {
    fn header(&self, name: &str) -> Option<&str> {
        self.0.headers.get(name)?.to_str().ok()
    }

    fn cookie(&self, name: &str) -> Option<&str> {
        // The validators' reader, so both agree on every header.
        crate::cookie_util::cookie_in(self.header("cookie")?, name)
    }

    fn method(&self) -> &str {
        self.0.method.as_str()
    }

    fn path(&self) -> &str {
        self.0.uri.path()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(content_type: Option<&str>, body: &str) -> EndpointRequest {
        let mut builder = http::Request::builder().uri("/x?code=a%20b&state=s");
        if let Some(ct) = content_type {
            builder = builder.header("content-type", ct);
        }
        let (parts, ()) = builder.body(()).unwrap().into_parts();
        EndpointRequest::new(parts, Bytes::from(body.to_string()), vec![])
    }

    #[derive(serde::Deserialize, Debug)]
    struct Body {
        #[allow(dead_code)]
        name: String,
    }

    #[test]
    fn json_bodies_follow_the_json_extractor_rules() {
        let status = |r: Result<Body, EndpointResponse>| r.unwrap_err().status();
        assert!(
            request(Some("application/json"), r#"{"name":"a"}"#)
                .json::<Body>()
                .is_ok()
        );
        assert!(
            request(
                Some("application/vnd.api+json; charset=utf-8"),
                r#"{"name":"a"}"#
            )
            .json::<Body>()
            .is_ok()
        );
        assert_eq!(
            status(request(None, r#"{"name":"a"}"#).json()),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            status(request(Some("text/plain"), r#"{"name":"a"}"#).json()),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            status(request(Some("application/json"), "{not json").json()),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status(request(Some("application/json"), r#"{"other":1}"#).json()),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    /// Found by fuzzing: the route table and the validators read cookies
    /// with one reader, so they agree on quoted and odd values.
    #[test]
    fn the_route_table_reads_cookies_as_the_validators_do() {
        use tempered_core::AuthRequest;
        for header in [
            "2=\" *  * \"",
            "=",
            "jwt=\"a\"; jwt=b",
            "jwt=\"",
            "a; jwt=x",
        ] {
            let (parts, ()) = http::Request::builder()
                .header("cookie", header)
                .body(())
                .unwrap()
                .into_parts();
            for name in ["2", "", "jwt"] {
                assert_eq!(
                    RequestHead(&parts).cookie(name).map(str::to_string),
                    crate::cookie_util::cookie_value(&parts, name),
                    "{header:?} / {name:?}"
                );
            }
        }
    }

    #[test]
    fn query_and_cookies_are_read_from_the_head() {
        let mut r = request(None, "");
        assert_eq!(r.query("code").as_deref(), Some("a b"));
        assert_eq!(r.query("missing"), None);
        r.parts
            .headers
            .insert("cookie", "a=1; oauth_state=\"xyz\" ;b=2".parse().unwrap());
        assert_eq!(r.head().cookie("oauth_state"), Some("xyz"));
        assert_eq!(r.head().cookie("b"), Some("2"));
        assert_eq!(r.head().cookie("c"), None);
    }
}
