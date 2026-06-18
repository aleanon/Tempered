use async_trait::async_trait;
use secrecy::ExposeSecret;
use tempered_core::{OAuthHttpClient, OAuthHttpError, OAuthProviderConfig, OAuthUserInfo};

/// Production [`OAuthHttpClient`] backed by `reqwest`.
///
/// Performs the standard authorization-code token exchange (form-encoded POST)
/// and an OIDC-style userinfo `GET` with a bearer token.
#[derive(Clone, Default)]
pub struct ReqwestOAuthHttpClient {
    client: reqwest::Client,
}

impl ReqwestOAuthHttpClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl OAuthHttpClient for ReqwestOAuthHttpClient {
    async fn exchange_code(
        &self,
        config: &OAuthProviderConfig,
        code: &str,
    ) -> Result<String, OAuthHttpError> {
        let secret = config.client_secret.expose_secret();
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", config.redirect_uri.as_str()),
            ("client_id", config.client_id.as_str()),
            ("client_secret", secret.as_str()),
        ];

        let resp = self
            .client
            .post(&config.token_url)
            .header("accept", "application/json")
            .form(&params)
            .send()
            .await
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

        Ok(OAuthUserInfo { subject, email })
    }
}
