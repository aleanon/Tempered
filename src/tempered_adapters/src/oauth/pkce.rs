//! PKCE (Proof Key for Code Exchange, RFC 7636) with the `S256` method.
//!
//! The flow generates a random `code_verifier` per authorization request,
//! sends only its SHA-256 `code_challenge` on the front-channel redirect, and
//! reveals the verifier on the back-channel token request. An attacker who
//! intercepts the authorization `code` (or injects their own into a victim's
//! callback) cannot redeem it without the verifier, which never left the server.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use secrecy::Secret;
use sha2::{Digest, Sha256};

/// The only challenge method this library sends. `plain` is never used.
pub const CODE_CHALLENGE_METHOD: &str = "S256";

/// A fresh high-entropy verifier: 32 random bytes, base64url-encoded without
/// padding (43 characters, the form RFC 7636 §4.1 recommends).
pub(crate) fn generate_verifier() -> Secret<String> {
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    Secret::new(URL_SAFE_NO_PAD.encode(buf))
}

/// The `S256` challenge for a verifier: `BASE64URL(SHA256(ASCII(verifier)))`,
/// unpadded (RFC 7636 §4.2).
///
/// Public so that a test or mock provider can check a presented verifier
/// against the challenge it received.
pub fn pkce_challenge_s256(code_verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn challenge_matches_the_rfc_7636_appendix_b_vector() {
        assert_eq!(
            pkce_challenge_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn verifier_is_43_unreserved_characters_and_unique() {
        let a = generate_verifier();
        let b = generate_verifier();
        let a = a.expose_secret();
        // RFC 7636 §4.1: 43..=128 chars from [A-Z a-z 0-9 - . _ ~].
        assert_eq!(a.len(), 43);
        assert!(
            a.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~'))
        );
        assert_ne!(a, b.expose_secret());
    }
}
