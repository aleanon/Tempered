use async_trait::async_trait;
use secrecy::ExposeSecret;
use tempered_core::{OAuthHttpClient, OAuthHttpError, OAuthProviderConfig, OAuthUserInfo};

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
    ) -> Result<String, OAuthHttpError> {
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

        json.get("access_token")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| OAuthHttpError::TokenExchange("missing access_token in response".into()))
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

        // OIDC providers expose `sub`; some OAuth2-only providers use `id`.
        let subject = json
            .get("sub")
            .or_else(|| json.get("id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| OAuthHttpError::UserInfo("missing sub/id in userinfo".into()))?
            .to_string();

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
}
