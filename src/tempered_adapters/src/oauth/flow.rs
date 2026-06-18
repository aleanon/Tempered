//! Framework-agnostic OAuth2 / OIDC authorization-code flow.
//!
//! Design note: rather than forcing OAuth's redirect flow through the
//! credentials-based [`AuthenticationScheme::login`](tempered_core::AuthenticationScheme),
//! this flow **verifies the provider identity and yields a domain [`Email`]**.
//! The application then issues whatever token its primary scheme uses (a JWT, a
//! session, …). This matches the library's "composition is a user concern"
//! stance and keeps OAuth decoupled from token delivery.
//!
//! All outbound provider calls go through the [`OAuthHttpClient`] port, so the
//! entire flow is unit-testable offline with a mock client.

use std::collections::HashMap;

use rand::RngCore;
use secrecy::Secret;
use tempered_core::{
    Email, OAuthHttpClient, OAuthIdentityStore, OAuthProviderConfig, OAuthStateStore, UserError,
};
use thiserror::Error;

/// The result of [`OAuthFlow::begin`].
///
/// `state` must be **bound to the initiating browser** by the delivery layer —
/// set it as an `HttpOnly; Secure; SameSite=Lax` cookie (e.g. `oauth_state`) on
/// the redirect response. On the callback, pass that cookie's value to
/// [`OAuthFlow::complete`] as `cookie_state`; the flow rejects the request
/// unless it matches the `state` query parameter. Without this binding the
/// server-side store alone would let any browser complete any pending flow
/// (login CSRF).
pub struct AuthorizationRequest {
    pub authorize_url: String,
    pub state: String,
}

pub struct OAuthFlow<ST, ID, HC> {
    state_store: ST,
    identity_store: ID,
    http_client: HC,
    providers: HashMap<String, OAuthProviderConfig>,
}

impl<ST, ID, HC> OAuthFlow<ST, ID, HC>
where
    ST: OAuthStateStore,
    ID: OAuthIdentityStore,
    HC: OAuthHttpClient,
{
    pub fn new(state_store: ST, identity_store: ID, http_client: HC) -> Self {
        Self {
            state_store,
            identity_store,
            http_client,
            providers: HashMap::new(),
        }
    }

    /// Register a provider; keyed by `config.name`.
    pub fn with_provider(mut self, config: OAuthProviderConfig) -> Self {
        self.providers.insert(config.name.clone(), config);
        self
    }

    /// Step 1: build the provider authorize URL and persist the anti-CSRF state.
    ///
    /// The returned [`AuthorizationRequest::state`] must be bound to the
    /// initiating browser (see that type's docs) and presented back to
    /// [`complete`](Self::complete).
    pub async fn begin(&self, provider: &str) -> Result<AuthorizationRequest, OAuthFlowError> {
        let config = self.provider(provider)?;
        let state = random_state();
        self.state_store
            .store_state(state.clone())
            .await
            .map_err(|e| OAuthFlowError::State(e.to_string()))?;
        Ok(AuthorizationRequest {
            authorize_url: build_authorize_url(config, &state),
            state,
        })
    }

    /// Step 2: validate state, exchange the code, fetch userinfo, link the
    /// identity, and return the verified local email.
    ///
    /// `query_state` is the `state` returned by the provider on the callback;
    /// `cookie_state` is the value previously bound to the initiating browser
    /// (see [`AuthorizationRequest`]). The two must match, which proves the same
    /// browser that began the flow is completing it.
    pub async fn complete(
        &self,
        provider: &str,
        code: &str,
        query_state: &str,
        cookie_state: &str,
    ) -> Result<Email, OAuthFlowError> {
        let config = self.provider(provider)?;

        // Bind the callback to the initiating browser before trusting `state`.
        if cookie_state.is_empty() || !constant_time_eq(query_state, cookie_state) {
            return Err(OAuthFlowError::InvalidState);
        }

        self.state_store
            .consume_state(query_state)
            .await
            .map_err(|_| OAuthFlowError::InvalidState)?;

        let access_token = self.http_client.exchange_code(config, code).await?;
        let info = self.http_client.fetch_user_info(config, &access_token).await?;

        let email = Email::try_from(Secret::new(info.email))?;
        self.identity_store
            .link_identity(provider.to_string(), info.subject, email.clone())
            .await
            .map_err(|e| OAuthFlowError::Identity(e.to_string()))?;

        Ok(email)
    }

    /// Look up the local email previously linked to a provider identity.
    pub async fn linked_email(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<Email>, OAuthFlowError> {
        self.identity_store
            .find_email(provider, subject)
            .await
            .map_err(|e| OAuthFlowError::Identity(e.to_string()))
    }

    fn provider(&self, name: &str) -> Result<&OAuthProviderConfig, OAuthFlowError> {
        self.providers
            .get(name)
            .ok_or_else(|| OAuthFlowError::UnknownProvider(name.to_string()))
    }
}

fn random_state() -> String {
    let mut buf = [0u8; 16];
    rand::rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Length-independent comparison so a mismatch doesn't leak via timing.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn build_authorize_url(config: &OAuthProviderConfig, state: &str) -> String {
    let mut url =
        reqwest::Url::parse(&config.auth_url).expect("provider auth_url must be a valid URL");
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", &config.redirect_uri)
        .append_pair("scope", &config.scopes.join(" "))
        .append_pair("state", state);
    url.to_string()
}

#[derive(Debug, Error)]
pub enum OAuthFlowError {
    #[error("Unknown OAuth provider: {0}")]
    UnknownProvider(String),
    #[error("Invalid or expired OAuth state")]
    InvalidState,
    #[error("OAuth HTTP error: {0}")]
    Http(#[from] tempered_core::OAuthHttpError),
    #[error("Invalid email from provider: {0}")]
    Email(#[from] UserError),
    #[error("State store error: {0}")]
    State(String),
    #[error("Identity store error: {0}")]
    Identity(String),
}

impl tempered_core::IntoStatusMessage for OAuthFlowError {
    fn into_status_message(self) -> (http::StatusCode, String) {
        match self {
            OAuthFlowError::UnknownProvider(p) => {
                (http::StatusCode::NOT_FOUND, format!("Unknown provider: {}", p))
            }
            OAuthFlowError::InvalidState => (
                http::StatusCode::BAD_REQUEST,
                "Invalid or expired OAuth state".to_string(),
            ),
            OAuthFlowError::Email(e) => (http::StatusCode::BAD_REQUEST, e.to_string()),
            OAuthFlowError::Http(e) => (http::StatusCode::BAD_GATEWAY, e.to_string()),
            OAuthFlowError::State(m) | OAuthFlowError::Identity(m) => {
                (http::StatusCode::INTERNAL_SERVER_ERROR, m)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::hashmap_oauth_identity_store::HashMapOAuthIdentityStore;
    use crate::persistence::hashmap_oauth_state_store::HashMapOAuthStateStore;
    use async_trait::async_trait;
    use tempered_core::{OAuthHttpError, OAuthUserInfo};

    #[derive(Clone)]
    struct MockClient {
        subject: String,
        email: String,
    }

    #[async_trait]
    impl OAuthHttpClient for MockClient {
        async fn exchange_code(
            &self,
            _config: &OAuthProviderConfig,
            _code: &str,
        ) -> Result<String, OAuthHttpError> {
            Ok("access-token".to_string())
        }

        async fn fetch_user_info(
            &self,
            _config: &OAuthProviderConfig,
            _access_token: &str,
        ) -> Result<OAuthUserInfo, OAuthHttpError> {
            Ok(OAuthUserInfo {
                subject: self.subject.clone(),
                email: self.email.clone(),
            })
        }
    }

    fn provider() -> OAuthProviderConfig {
        OAuthProviderConfig {
            name: "google".to_string(),
            client_id: "cid".to_string(),
            client_secret: Secret::new("secret".to_string()),
            auth_url: "https://accounts.example.com/authorize".to_string(),
            token_url: "https://accounts.example.com/token".to_string(),
            userinfo_url: "https://accounts.example.com/userinfo".to_string(),
            redirect_uri: "https://app.example.com/oauth/google/callback".to_string(),
            scopes: vec!["openid".to_string(), "email".to_string()],
        }
    }

    fn flow(email: &str) -> OAuthFlow<HashMapOAuthStateStore, HashMapOAuthIdentityStore, MockClient>
    {
        OAuthFlow::new(
            HashMapOAuthStateStore::new(),
            HashMapOAuthIdentityStore::new(),
            MockClient {
                subject: "sub-123".to_string(),
                email: email.to_string(),
            },
        )
        .with_provider(provider())
    }

    fn state_from_url(url: &str) -> String {
        reqwest::Url::parse(url)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == "state")
            .unwrap()
            .1
            .to_string()
    }

    #[tokio::test]
    async fn begin_builds_url_with_state_and_client_id() {
        let f = flow("user@example.com");
        let req = f.begin("google").await.unwrap();
        assert!(req.authorize_url.contains("client_id=cid"));
        assert!(req.authorize_url.contains("response_type=code"));
        assert!(req.authorize_url.contains("state="));
        // The returned state is the one embedded in the URL (to be cookie-bound).
        assert_eq!(state_from_url(&req.authorize_url), req.state);
    }

    #[tokio::test]
    async fn full_flow_links_identity_and_returns_email() {
        let f = flow("user@example.com");
        let req = f.begin("google").await.unwrap();

        // cookie_state == query_state proves the same browser is completing.
        let email = f
            .complete("google", "auth-code", &req.state, &req.state)
            .await
            .unwrap();
        let expected = Email::try_from(Secret::new("user@example.com".to_string())).unwrap();
        assert_eq!(email, expected);

        let linked = f.linked_email("google", "sub-123").await.unwrap();
        assert_eq!(linked, Some(expected));
    }

    #[tokio::test]
    async fn replayed_state_is_rejected() {
        let f = flow("user@example.com");
        let req = f.begin("google").await.unwrap();

        f.complete("google", "code", &req.state, &req.state)
            .await
            .unwrap();
        let replay = f.complete("google", "code", &req.state, &req.state).await;
        assert!(matches!(replay, Err(OAuthFlowError::InvalidState)));
    }

    #[tokio::test]
    async fn callback_with_mismatched_cookie_state_is_rejected() {
        let f = flow("user@example.com");
        let req = f.begin("google").await.unwrap();

        // Attacker injects a valid pending `state` from a different browser, but
        // cannot forge the victim's `oauth_state` cookie.
        let result = f
            .complete("google", "code", &req.state, "attacker-cookie")
            .await;
        assert!(matches!(result, Err(OAuthFlowError::InvalidState)));
    }

    #[tokio::test]
    async fn unknown_provider_errors() {
        let f = flow("user@example.com");
        assert!(matches!(
            f.begin("github").await,
            Err(OAuthFlowError::UnknownProvider(_))
        ));
    }
}
