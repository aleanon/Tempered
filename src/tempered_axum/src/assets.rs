//! The static-file fallback, minus hidden files.
//!
//! `ServeDir` serves whatever is in the directory, dotfiles included, so an
//! `assets_dir` of `"."` would hand out `.env` or `.git/config`. Requests
//! whose path has a segment starting with `.` get a 404 before they reach
//! it. `/.well-known/` stays open: standard files live there
//! (`security.txt`, passkey related origins, app links), and the segments
//! inside it are still checked.
//!
//! The check runs on the percent-decoded path, as `ServeDir` decodes before
//! it touches the filesystem: `/%2Eenv` and `/a%2F.env` are hidden too.

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

/// 404 for a hidden path, otherwise on to the static files.
pub(crate) async fn hide_dotfiles(request: Request, next: Next) -> Response {
    if is_hidden(request.uri().path()) {
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(request).await
}

/// Whether any segment of the decoded `path` starts with `.`, apart from a
/// leading `.well-known`.
fn is_hidden(path: &str) -> bool {
    let decoded = percent_decode(path);
    decoded
        .split(['/', '\\'])
        .filter(|segment| !segment.is_empty())
        .enumerate()
        .any(|(i, segment)| segment.starts_with('.') && !(i == 0 && segment == ".well-known"))
}

/// `%XX` escapes decoded, everything else kept. Invalid escapes stay as they
/// are, and bytes that are not UTF-8 are replaced; neither can turn a
/// segment into one that starts with `.` where `ServeDir` would see none.
fn percent_decode(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(byte) = bytes
                .get(i + 1..i + 3)
                .and_then(|hex| std::str::from_utf8(hex).ok())
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        {
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::is_hidden;

    #[test]
    fn dotfiles_and_dot_directories_are_hidden_however_they_are_spelled() {
        for path in [
            "/.env",
            "/.git/config",
            "/static/.htpasswd",
            "/%2Eenv",
            "/%2eenv",
            "/a%2F.env",
            "/a%5C.env",
            "/../secret",
            "/.well-known/.hidden",
            "/x/.well-known/thing",
        ] {
            assert!(is_hidden(path), "{path}");
        }
    }

    #[test]
    fn ordinary_paths_and_well_known_are_served() {
        for path in [
            "/",
            "/index.html",
            "/app.js",
            "/img/logo.v2.png",
            "/a..b",
            "/.well-known/security.txt",
            "/.well-known/webauthn",
            "/%41pp.js",
        ] {
            assert!(!is_hidden(path), "{path}");
        }
    }
}
