//! Framework-neutral cookie parsing over the `cookie` crate.
//!
//! Validators need to read a named cookie's value out of a request's `Cookie`
//! header without pulling in a web framework. axum-extra's `CookieJar` is just a
//! thin wrapper over this same `cookie` crate, so using it directly keeps the
//! adapter layer framework-agnostic.

use cookie::Cookie;

/// A `Set-Cookie` value that deletes the cookie `name`. The attributes match
/// the ones every cookie this crate sets uses (`Path=/`), which a browser
/// needs to find the cookie to delete.
pub fn expired_cookie(name: &str) -> String {
    format!("{name}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0")
}

/// Return the value of the cookie named `name` from the request's `Cookie`
/// header, or `None` if the header is missing/unparseable or the cookie is
/// absent. An empty value is returned as-is (callers decide how to treat it).
pub fn cookie_value(parts: &http::request::Parts, name: &str) -> Option<String> {
    let header = parts.headers.get(http::header::COOKIE)?.to_str().ok()?;
    cookie_in(header, name).map(str::to_string)
}

/// The value of the first cookie named `name` in a `Cookie` header's value,
/// without the double quotes RFC 6265 allows around it. The one cookie
/// reader: the validators and the route table both use it, so a request
/// cannot be authenticated by one cookie and log out another.
pub fn cookie_in<'h>(header: &'h str, name: &str) -> Option<&'h str> {
    let value = Cookie::split_parse(header)
        .filter_map(Result::ok)
        .find(|c| c.name() == name)
        .and_then(|c| c.value_raw())?;
    Some(
        value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(value),
    )
}
