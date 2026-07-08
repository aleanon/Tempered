//! Framework-neutral cookie parsing over the `cookie` crate.
//!
//! Validators need to read a named cookie's value out of a request's `Cookie`
//! header without pulling in a web framework. axum-extra's `CookieJar` is just a
//! thin wrapper over this same `cookie` crate, so using it directly keeps the
//! adapter layer framework-agnostic.

use cookie::Cookie;

/// Return the value of the cookie named `name` from the request's `Cookie`
/// header, or `None` if the header is missing/unparseable or the cookie is
/// absent. An empty value is returned as-is (callers decide how to treat it).
pub fn cookie_value(parts: &http::request::Parts, name: &str) -> Option<String> {
    let header = parts.headers.get(http::header::COOKIE)?.to_str().ok()?;
    Cookie::split_parse(header)
        .filter_map(Result::ok)
        .find(|c| c.name() == name)
        .map(|c| c.value().to_string())
}
