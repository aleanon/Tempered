use async_trait::async_trait;
use secrecy::{ExposeSecret, Secret};
use tempered_core::{
    OAuthHttpClient, OAuthHttpError, OAuthProviderConfig, OAuthUserInfo, TokenResponse,
};

/// Production [`OAuthHttpClient`] backed by `reqwest`.
///
/// Performs the standard authorization-code token exchange with PKCE (form-encoded POST)
/// and an OIDC-style userinfo `GET` with a bearer token.
///
/// The client times out (5 s to connect, 10 s per request), so a slow or
/// hung provider cannot hold a callback open indefinitely, and it follows no
/// redirects: a 307/308 from the token endpoint would resend the code, the
/// PKCE verifier and the client secret to wherever it points.
#[derive(Clone)]
pub struct ReqwestOAuthHttpClient {
    client: reqwest::Client,
}

const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

impl ReqwestOAuthHttpClient {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            // Some provider APIs (GitHub's) refuse requests without one.
            .user_agent(concat!("tempered/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("the TLS backend failed to initialise");
        Self { client }
    }

    /// Use your own `reqwest::Client` (proxy, custom roots, other timeouts).
    /// Keep its redirect policy at `Policy::none()`, for the reason above.
    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }
}

impl Default for ReqwestOAuthHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OAuthHttpClient for ReqwestOAuthHttpClient {
    async fn exchange_code(
        &self,
        config: &OAuthProviderConfig,
        code: &str,
        code_verifier: &str,
    ) -> Result<TokenResponse, OAuthHttpError> {
        let secret = config.client_secret.expose_secret();
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", config.redirect_uri.as_str()),
            ("client_id", config.client_id.as_str()),
            ("client_secret", secret.as_str()),
            // PKCE (RFC 7636 §4.5): proves this token request comes from the
            // party that started the authorization request.
            ("code_verifier", code_verifier),
        ];

        let resp = self
            .client
            .post(&config.token_url)
            .header("accept", "application/json")
            .form(&params)
            .send()
            .await
            .map_err(|e| OAuthHttpError::TokenExchange(e.to_string()))?
            .error_for_status()
            .map_err(|e| OAuthHttpError::TokenExchange(e.to_string()))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| OAuthHttpError::TokenExchange(e.to_string()))?;

        let access_token = json
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                OAuthHttpError::TokenExchange("missing access_token in response".into())
            })?;
        Ok(TokenResponse {
            access_token: Secret::new(access_token.to_string()),
            id_token: json
                .get("id_token")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        })
    }

    async fn fetch_user_info(
        &self,
        config: &OAuthProviderConfig,
        access_token: &str,
    ) -> Result<OAuthUserInfo, OAuthHttpError> {
        let resp = self
            .client
            .get(&config.userinfo_url)
            .bearer_auth(access_token)
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|e| OAuthHttpError::UserInfo(e.to_string()))?
            .error_for_status()
            .map_err(|e| OAuthHttpError::UserInfo(e.to_string()))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| OAuthHttpError::UserInfo(e.to_string()))?;

        // OIDC providers expose `sub`; some OAuth2-only providers use `id`,
        // GitHub as a number.
        let subject = match json.get("sub").or_else(|| json.get("id")) {
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(serde_json::Value::Number(n)) => n.to_string(),
            _ => {
                return Err(OAuthHttpError::UserInfo(
                    "missing sub/id in userinfo".into(),
                ));
            }
        };

        // A provider with an emails endpoint (GitHub) lists the addresses and
        // which are verified; the primary one is the account's.
        if let Some(url) = &config.emails_url {
            let emails = self.get(url, Some(access_token)).await?;
            let primary = emails
                .as_array()
                .and_then(|list| {
                    list.iter()
                        .find(|e| e.get("primary").and_then(|p| p.as_bool()) == Some(true))
                })
                .ok_or_else(|| OAuthHttpError::UserInfo("no primary address".into()))?;
            let email = primary
                .get("email")
                .and_then(|v| v.as_str())
                .ok_or_else(|| OAuthHttpError::UserInfo("primary address has no email".into()))?;
            return Ok(OAuthUserInfo {
                subject,
                email: email.to_string(),
                email_verified: primary.get("verified").and_then(|v| v.as_bool()) == Some(true),
            });
        }

        let email = json
            .get("email")
            .and_then(|v| v.as_str())
            .ok_or_else(|| OAuthHttpError::UserInfo("missing email in userinfo".into()))?
            .to_string();

        // Default to false when absent so providers that don't assert
        // verification are treated as unverified (and rejected by the flow).
        let email_verified = json
            .get("email_verified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        Ok(OAuthUserInfo {
            subject,
            email,
            email_verified,
        })
    }

    async fn fetch_json(&self, url: &str) -> Result<serde_json::Value, OAuthHttpError> {
        self.get(url, None).await
    }
}

impl ReqwestOAuthHttpClient {
    /// `GET` JSON, with a bearer token when given.
    async fn get(
        &self,
        url: &str,
        bearer: Option<&str>,
    ) -> Result<serde_json::Value, OAuthHttpError> {
        let mut request = self.client.get(url).header("accept", "application/json");
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        request
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| OAuthHttpError::Fetch(e.to_string()))?
            .json()
            .await
            .map_err(|e| OAuthHttpError::Fetch(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn config(server: &MockServer, emails: bool) -> OAuthProviderConfig {
        OAuthProviderConfig {
            name: "gh".into(),
            client_id: "c".into(),
            client_secret: Secret::new("s".into()),
            auth_url: format!("{}/authorize", server.uri()),
            token_url: format!("{}/token", server.uri()),
            userinfo_url: format!("{}/user", server.uri()),
            redirect_uri: "http://localhost/cb".into(),
            scopes: vec![],
            oidc: None,
            emails_url: emails.then(|| format!("{}/user/emails", server.uri())),
        }
    }

    #[tokio::test]
    async fn the_token_response_keeps_the_id_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "access_token": "at", "id_token": "header.body.sig" }),
            ))
            .mount(&server)
            .await;
        let tokens = ReqwestOAuthHttpClient::new()
            .exchange_code(&config(&server, false), "code", "verifier")
            .await
            .unwrap();
        assert_eq!(tokens.access_token.expose_secret(), "at");
        assert_eq!(tokens.id_token.as_deref(), Some("header.body.sig"));
    }

    #[tokio::test]
    async fn a_github_style_user_takes_the_primary_address_and_its_verified_flag() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .and(header("authorization", "Bearer at"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "id": 583231, "login": "octocat", "email": null }),
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/emails"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                { "email": "old@example.com", "primary": false, "verified": true },
                { "email": "octo@example.com", "primary": true, "verified": true },
            ])))
            .mount(&server)
            .await;
        let info = ReqwestOAuthHttpClient::new()
            .fetch_user_info(&config(&server, true), "at")
            .await
            .unwrap();
        assert_eq!(info.subject, "583231");
        assert_eq!(info.email, "octo@example.com");
        assert!(info.email_verified);
    }
}
