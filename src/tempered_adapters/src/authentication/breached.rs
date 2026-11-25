//! Refuse passwords that have appeared in data breaches, using the Have I
//! Been Pwned range API (k-anonymity: only the first five hex digits of the
//! password's SHA-1 leave the server, and the reply is padded).

use async_trait::async_trait;
use secrecy::ExposeSecret;
use sha1::{Digest, Sha1};
use tempered_core::{Email, Password, PasswordPolicy, PasswordRejected};

const DEFAULT_RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";

/// A [`PasswordPolicy`] that refuses passwords found in the HIBP breach
/// corpus.
///
/// If the API cannot be reached (or answers in a way it should not), the
/// password is accepted and the failure logged: a third-party outage
/// should not stop signups and password changes.
#[derive(Clone)]
pub struct BreachedPasswordCheck {
    client: reqwest::Client,
    range_url: String,
}

impl Default for BreachedPasswordCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl BreachedPasswordCheck {
    pub fn new() -> Self {
        Self::with_range_url(DEFAULT_RANGE_URL)
    }

    /// Ask another range endpoint (a mirror, or a test server). It gets the
    /// prefix appended.
    pub fn with_range_url(range_url: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(3))
            .timeout(std::time::Duration::from_secs(5))
            .user_agent(concat!("tempered/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("the TLS backend failed to initialise");
        Self {
            client,
            range_url: range_url.into(),
        }
    }

    /// How often the password appears in breaches; `None` if the API could
    /// not tell.
    async fn times_seen(&self, password: &Password) -> Option<u64> {
        let digest = Sha1::digest(password.as_ref().expose_secret().as_bytes());
        let hex: String = digest.iter().map(|b| format!("{b:02X}")).collect();
        let (prefix, suffix) = hex.split_at(5);
        let reply = self
            .client
            .get(format!("{}{prefix}", self.range_url))
            // The reply is padded with fake entries, so its size does not
            // tell an eavesdropper how common the prefix is.
            .header("Add-Padding", "true")
            .send()
            .await
            .and_then(reqwest::Response::error_for_status);
        let body = match reply {
            Ok(response) => response.text().await.ok()?,
            Err(e) => {
                tracing::warn!(error = %e, "breached-password check unavailable; accepting");
                return None;
            }
        };
        Some(
            body.lines()
                .filter_map(|line| line.trim().split_once(':'))
                .find(|(s, _)| s.eq_ignore_ascii_case(suffix))
                .and_then(|(_, count)| count.trim().parse().ok())
                .unwrap_or(0),
        )
    }
}

#[async_trait]
impl PasswordPolicy for BreachedPasswordCheck {
    async fn check(&self, _email: &Email, password: &Password) -> Result<(), PasswordRejected> {
        match self.times_seen(password).await {
            Some(seen) if seen > 0 => Err(PasswordRejected(
                "This password has appeared in a data breach; choose another".to_string(),
            )),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::Secret;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn password(s: &str) -> Password {
        Password::try_from(Secret::new(s.to_string())).unwrap()
    }

    fn email() -> Email {
        Email::try_from(Secret::new("a@example.com".to_string())).unwrap()
    }

    #[tokio::test]
    async fn a_breached_password_is_refused_and_only_the_prefix_is_sent() {
        // SHA-1("password1") = E38AD214943DAAD1D64C102FAEC29DE4AFE9DA3D
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/range/E38AD"))
            .and(header("Add-Padding", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n214943DAAD1D64C102FAEC29DE4AFE9DA3D:2427710\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0",
            ))
            .mount(&server)
            .await;
        let check = BreachedPasswordCheck::with_range_url(format!("{}/range/", server.uri()));
        assert!(check.check(&email(), &password("password1")).await.is_err());
    }

    #[tokio::test]
    async fn an_unseen_password_or_a_padding_entry_is_accepted() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                // A padding entry for the right suffix would read ":0".
                "214943DAAD1D64C102FAEC29DE4AFE9DA3D:0",
            ))
            .mount(&server)
            .await;
        let check = BreachedPasswordCheck::with_range_url(format!("{}/range/", server.uri()));
        assert!(check.check(&email(), &password("password1")).await.is_ok());
        assert!(
            check
                .check(&email(), &password("a long and unusual passphrase"))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn an_outage_accepts_the_password() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let check = BreachedPasswordCheck::with_range_url(format!("{}/range/", server.uri()));
        assert!(check.check(&email(), &password("password1")).await.is_ok());
    }
}
