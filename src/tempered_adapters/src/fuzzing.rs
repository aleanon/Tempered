//! Entry points for the fuzz targets in `fuzz/` (feature `fuzzing`; not
//! public API). Each one takes bytes an attacker controls and must never
//! panic, whatever they are.

use secrecy::Secret;

use crate::auth_validation::local_jwt_validator::{JwtAuthConfig, bearer_token, decode_signed};
use crate::cookie_util::cookie_value;

/// The domain parsers: addresses, API keys, session ids, mailed tokens,
/// 2FA codes and attempt ids.
pub fn domain(input: &str) {
    let _ = tempered_core::Email::try_from(Secret::new(input.to_string()));
    let _ = tempered_core::ApiKeyId::parse(input);
    let _ = tempered_core::domain::api_key::split_presented_key(input);
    let _ = tempered_core::SessionId::parse(input);
    let _ = tempered_core::PasswordResetToken::parse(input);
    let _ = tempered_core::EmailVerificationToken::parse(input);
    let _ = tempered_core::TwoFaCode::parse(input.to_string());
    let _ = tempered_core::TwoFaAttemptId::parse(input);
}

/// A request's credentials: the `Cookie` and `Authorization` headers, then
/// whatever they carry as a signed JWT.
pub fn request_credentials(cookie: &[u8], authorization: &[u8]) {
    let mut request = http::Request::builder();
    if let Ok(value) = http::HeaderValue::from_bytes(cookie) {
        request = request.header(http::header::COOKIE, value);
    }
    if let Ok(value) = http::HeaderValue::from_bytes(authorization) {
        request = request.header(http::header::AUTHORIZATION, value);
    }
    let Ok(request) = request.body(()) else {
        return;
    };
    let (parts, ()) = request.into_parts();
    let config = JwtAuthConfig {
        jwt_cookie_name: "jwt".to_string(),
        jwt_secret: Secret::new("a-fuzzing-secret-that-is-long-enough".to_string()),
        token_ttl_in_seconds: 3600,
        audience: Some("aud".to_string()),
        issuer: Some("iss".to_string()),
    };
    for token in [cookie_value(&parts, "jwt"), bearer_token(&parts).ok()]
        .into_iter()
        .flatten()
    {
        let _ = decode_signed(&token, &config);
    }
}

/// The two cookie readers agree: the validators' (`cookie_util`, the
/// `cookie` crate) and the route table's (`AuthRequest::cookie`, which
/// logout uses to pick the token it revokes). If they disagreed, a request
/// could be authenticated by one cookie and log out another.
///
/// # Panics
///
/// When they disagree on `name` (the fuzzer's finding).
pub fn cookies_agree(header: &[u8], name: &str) {
    use tempered_core::AuthRequest;
    let Ok(value) = http::HeaderValue::from_bytes(header) else {
        return;
    };
    let Ok(request) = http::Request::builder()
        .header(http::header::COOKIE, value)
        .body(())
    else {
        return;
    };
    let (parts, ()) = request.into_parts();
    let validators = cookie_value(&parts, name);
    let routes = crate::endpoints::RequestHead(&parts)
        .cookie(name)
        .map(str::to_string);
    assert_eq!(
        validators, routes,
        "cookie readers disagree on {name:?} in {header:?}"
    );
}

/// The browser's WebAuthn JSON, against ceremonies the verifier started.
#[cfg(feature = "passkeys-webauthn")]
pub fn webauthn(json: &[u8]) {
    use tempered_core::{CredentialId, PasskeyCredential, WebAuthnVerifier};

    use crate::passkey::WebAuthnRsVerifier;

    let Ok(response) = serde_json::from_slice::<serde_json::Value>(json) else {
        return;
    };
    let verifier = WebAuthnRsVerifier::new(
        "example.com",
        "https://example.com",
        Secret::new(vec![7; 32]),
    )
    .expect("a valid relying party");
    let email = tempered_core::Email::try_from(Secret::new("a@example.com".to_string()))
        .expect("a valid address");
    if let Ok(start) = verifier.start_registration(&email, &[]) {
        let _ = verifier.finish_registration(&start.state, &response);
    }
    if let Ok(start) = verifier.start_authentication(&[]) {
        let stored = PasskeyCredential {
            credential_id: CredentialId("c".to_string()),
            owner: email,
            credential_data: json.to_vec(),
            sign_count: 0,
            name: None,
        };
        let _ = verifier.finish_authentication(&start.state, &response, &stored);
    }
}

#[cfg(test)]
mod tests {
    // The targets must not panic on the obvious edge cases either.
    #[test]
    fn edge_cases_do_not_panic() {
        for input in [
            "",
            "\0",
            "@",
            "tmp_",
            "a.b.c",
            "Bearer ",
            "é",
            &"9".repeat(10_000),
        ] {
            super::domain(input);
            super::request_credentials(input.as_bytes(), input.as_bytes());
            super::cookies_agree(format!("jwt={input}; a=b").as_bytes(), "jwt");
            // Found by the fuzzer: a pair with an empty name.
            super::cookies_agree(b"=", "");
            super::request_credentials(
                format!("jwt={input}").as_bytes(),
                format!("Bearer {input}").as_bytes(),
            );
        }
    }
}
