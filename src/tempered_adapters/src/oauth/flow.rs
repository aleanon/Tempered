//! Framework-agnostic OAuth2 / OIDC authorization-code flow.
//!
//! Design note: rather than forcing OAuth's redirect flow through the
//! credentials-based [`AuthenticationScheme::login`](tempered_core::AuthenticationScheme),
//! this flow **verifies the provider identity and yields a domain [`Email`]**.
//! The application then issues whatever token its primary scheme uses (a JWT, a
//! session, …). This matches the library's "composition is a user concern"
//! stance and keeps OAuth decoupled from token delivery.
//!
//! Every authorization request uses **PKCE** (RFC 7636, `S256`): a per-request
//! verifier is stored server-side with the `state`, its challenge goes on the
//! authorize redirect, and the verifier is revealed only on the token exchange.
//!
//! All outbound provider calls go through the [`OAuthHttpClient`] port, so the
//! entire flow is unit-testable offline with a mock client.

use std::collections::HashMap;

use rand::RngCore;
use secrecy::{ExposeSecret, Secret};
use tempered_core::{
    ClassifyError, Email, ErrorCategory, OAuthHttpClient, OAuthIdentityStore,
    OAuthIdentityStoreError, OAuthProviderConfig, OAuthStateStore, PendingAuthorization, UserError,
    constant_time_eq,
};
use thiserror::Error;

use super::pkce::{CODE_CHALLENGE_METHOD, generate_verifier, pkce_challenge_s256};

// The flow's [`begin`](OAuthFlow::begin) returns the framework-agnostic
// [`AuthorizationRequest`] defined in `tempered_core` (so the `SupportsOAuth2`
// capability and the HTTP layer share one type). Re-exported from this module's
// original path for backwards compatibility.
pub use tempered_core::AuthorizationRequest;

/// A provider identity the flow has verified: the callback was genuine, the
/// code exchanged, and the provider vouches for the email.
///
/// Only [`OAuthFlow::complete`] can produce one, so [`OAuthFlow::link`] cannot
/// be handed an identity nobody verified.
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    provider: String,
    subject: String,
    email: Email,
    already_linked: bool,
}

impl VerifiedIdentity {
    /// The local account this identity logs in to.
    pub fn email(&self) -> &Email {
        &self.email
    }

    /// Whether this identity was linked to that account before this login.
    /// `false` means this is the first time it is used to reach the account.
    pub fn already_linked(&self) -> bool {
        self.already_linked
    }
}

#[derive(Clone)]
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

    /// Step 1: build the provider authorize URL and persist the anti-CSRF state
    /// together with a fresh PKCE verifier.
    ///
    /// The returned [`AuthorizationRequest::state`] must be bound to the
    /// initiating browser (see that type's docs) and presented back to
    /// [`complete`](Self::complete).
    pub async fn begin(&self, provider: &str) -> Result<AuthorizationRequest, OAuthFlowError> {
        let config = self.provider(provider)?;
        let state = random_state();
        let code_verifier = generate_verifier();
        // Only the challenge travels through the browser; the verifier stays here.
        let code_challenge = pkce_challenge_s256(code_verifier.expose_secret());
        self.state_store
            .store_state(
                state.clone(),
                PendingAuthorization {
                    provider: config.name.clone(),
                    code_verifier,
                },
            )
            .await
            .map_err(|e| OAuthFlowError::State(e.to_string()))?;
        Ok(AuthorizationRequest {
            authorize_url: build_authorize_url(config, &state, &code_challenge),
            state,
        })
    }

    /// Step 2: validate state, exchange the code, fetch userinfo, and return
    /// the verified provider identity.
    ///
    /// This does **not** link the identity. The caller decides what the login
    /// means for the local account (create it, or secure an unproven one) and
    /// then calls [`link`](Self::link), so a failure in between never leaves an
    /// identity linked to an account that was not made safe first.
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
    ) -> Result<VerifiedIdentity, OAuthFlowError> {
        let config = self.provider(provider)?;

        // Bind the callback to the initiating browser before trusting `state`.
        if cookie_state.is_empty() || !constant_time_eq(query_state, cookie_state) {
            return Err(OAuthFlowError::InvalidState);
        }

        // Single-use: consuming the state yields the authorization request it
        // was issued for, including that request's PKCE verifier.
        let pending = self
            .state_store
            .consume_state(query_state)
            .await
            .map_err(|_| OAuthFlowError::InvalidState)?;

        // The callback must arrive on the route of the provider the request was
        // sent to. Otherwise a state issued for provider A could be completed
        // on provider B's callback, sending A's verifier (and the code) to B's
        // token endpoint and taking the identity from B (provider mix-up).
        // Checked before any outbound call; the state is spent either way.
        if !constant_time_eq(&pending.provider, &config.name) {
            return Err(OAuthFlowError::InvalidState);
        }
        let code_verifier = pending.code_verifier;

        let access_token = self
            .http_client
            .exchange_code(config, code, code_verifier.expose_secret())
            .await?;
        let info = self
            .http_client
            .fetch_user_info(config, &access_token)
            .await?;

        // Never derive identity from an unverified provider email: an attacker
        // could register a victim's address (unverified) at the provider and
        // take over the linked local account.
        if !info.email_verified {
            return Err(OAuthFlowError::EmailNotVerified);
        }

        let email = Email::try_from(Secret::new(info.email))?;
        let already_linked = match self.linked_email(provider, &info.subject).await? {
            Some(linked) if linked == email => true,
            // The identity belongs to another account: never move it silently.
            Some(_) => return Err(OAuthFlowError::IdentityConflict),
            None => false,
        };

        Ok(VerifiedIdentity {
            provider: provider.to_string(),
            subject: info.subject,
            email,
            already_linked,
        })
    }

    /// Record a verified identity as a way to log in to its email's account.
    /// Idempotent for an identity that is already linked to that account.
    pub async fn link(&self, identity: &VerifiedIdentity) -> Result<(), OAuthFlowError> {
        self.identity_store
            .link_identity(
                identity.provider.clone(),
                identity.subject.clone(),
                identity.email.clone(),
            )
            .await
            .map_err(|e| match e {
                OAuthIdentityStoreError::AlreadyLinked => OAuthFlowError::IdentityConflict,
                other => OAuthFlowError::Identity(other.to_string()),
            })
    }

    /// Whether any provider identity is already linked to `email`'s account.
    pub async fn has_linked_identity(&self, email: &Email) -> Result<bool, OAuthFlowError> {
        self.identity_store
            .has_identity_for_email(email)
            .await
            .map_err(|e| OAuthFlowError::Identity(e.to_string()))
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

fn build_authorize_url(config: &OAuthProviderConfig, state: &str, code_challenge: &str) -> String {
    let mut url = url::Url::parse(&config.auth_url).expect("provider auth_url must be a valid URL");
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", &config.redirect_uri)
        .append_pair("scope", &config.scopes.join(" "))
        .append_pair("state", state)
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", CODE_CHALLENGE_METHOD);
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
    #[error("Provider did not assert a verified email")]
    EmailNotVerified,
    #[error("Identity already linked to a different account")]
    IdentityConflict,
    #[error("State store error: {0}")]
    State(String),
    #[error("Identity store error: {0}")]
    Identity(String),
}

impl ClassifyError for OAuthFlowError {
    fn classify(self) -> (ErrorCategory, String) {
        match self {
            OAuthFlowError::UnknownProvider(p) => {
                (ErrorCategory::NotFound, format!("Unknown provider: {}", p))
            }
            OAuthFlowError::InvalidState => (
                ErrorCategory::BadRequest,
                "Invalid or expired OAuth state".to_string(),
            ),
            OAuthFlowError::Email(e) => (ErrorCategory::BadRequest, e.to_string()),
            OAuthFlowError::EmailNotVerified => (
                ErrorCategory::Unauthorized,
                "Provider email is not verified".to_string(),
            ),
            OAuthFlowError::IdentityConflict => (
                ErrorCategory::Conflict,
                "Identity already linked to a different account".to_string(),
            ),
            // Don't leak provider/internal detail to clients; the full cause
            // stays available server-side via the error's Display (for logging).
            OAuthFlowError::Http(_) => (
                ErrorCategory::BadGateway,
                "OAuth provider error".to_string(),
            ),
            OAuthFlowError::State(_) | OAuthFlowError::Identity(_) => {
                (ErrorCategory::Internal, "Internal error".to_string())
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
    use std::sync::{Arc, Mutex};
    use tempered_core::{OAuthHttpError, OAuthUserInfo};

    #[derive(Clone)]
    struct MockClient {
        subject: String,
        email: String,
        email_verified: bool,
        /// The `code_verifier` presented on each token exchange, in order.
        seen_verifiers: Arc<Mutex<Vec<String>>>,
    }

    impl MockClient {
        fn new(subject: &str, email: &str, email_verified: bool) -> Self {
            Self {
                subject: subject.to_string(),
                email: email.to_string(),
                email_verified,
                seen_verifiers: Arc::default(),
            }
        }
    }

    #[async_trait]
    impl OAuthHttpClient for MockClient {
        async fn exchange_code(
            &self,
            _config: &OAuthProviderConfig,
            _code: &str,
            code_verifier: &str,
        ) -> Result<String, OAuthHttpError> {
            self.seen_verifiers
                .lock()
                .unwrap()
                .push(code_verifier.to_string());
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
                email_verified: self.email_verified,
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

    fn flow(
        email: &str,
    ) -> OAuthFlow<HashMapOAuthStateStore, HashMapOAuthIdentityStore, MockClient> {
        OAuthFlow::new(
            HashMapOAuthStateStore::new(),
            HashMapOAuthIdentityStore::new(),
            MockClient::new("sub-123", email, true),
        )
        .with_provider(provider())
    }

    fn query_param(url: &str, name: &str) -> String {
        url::Url::parse(url)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == name)
            .unwrap_or_else(|| panic!("authorize URL has no `{name}` parameter"))
            .1
            .to_string()
    }

    fn state_from_url(url: &str) -> String {
        query_param(url, "state")
    }

    #[tokio::test]
    async fn begin_sends_an_s256_pkce_challenge() {
        let f = flow("user@example.com");
        let req = f.begin("google").await.unwrap();
        assert_eq!(
            query_param(&req.authorize_url, "code_challenge_method"),
            "S256"
        );
        // 32-byte SHA-256 digest, base64url without padding.
        assert_eq!(query_param(&req.authorize_url, "code_challenge").len(), 43);
    }

    #[tokio::test]
    async fn token_exchange_presents_the_verifier_for_the_challenge_sent() {
        let f = flow("user@example.com");
        let req = f.begin("google").await.unwrap();
        let challenge = query_param(&req.authorize_url, "code_challenge");

        f.complete("google", "auth-code", &req.state, &req.state)
            .await
            .unwrap();

        let seen = f.http_client.seen_verifiers.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        // What the provider checks: S256(verifier) == the challenge it was sent.
        assert_eq!(pkce_challenge_s256(&seen[0]), challenge);
        // The verifier itself must never appear on the front channel.
        assert!(!req.authorize_url.contains(&seen[0]));
    }

    #[tokio::test]
    async fn each_authorization_request_gets_its_own_verifier() {
        let f = flow("user@example.com");
        let first = f.begin("google").await.unwrap();
        let second = f.begin("google").await.unwrap();
        assert_ne!(
            query_param(&first.authorize_url, "code_challenge"),
            query_param(&second.authorize_url, "code_challenge")
        );

        // Completing the second request presents the second request's verifier.
        f.complete("google", "code", &second.state, &second.state)
            .await
            .unwrap();
        let seen = f.http_client.seen_verifiers.lock().unwrap().clone();
        assert_eq!(
            pkce_challenge_s256(&seen[0]),
            query_param(&second.authorize_url, "code_challenge")
        );
    }

    #[tokio::test]
    async fn a_state_issued_for_one_provider_is_rejected_on_another() {
        let mut github = provider();
        github.name = "github".to_string();
        github.token_url = "https://github.example.com/token".to_string();
        let f = flow("user@example.com").with_provider(github);

        // Begun with google; the callback arrives on github's route.
        let req = f.begin("google").await.unwrap();
        let result = f.complete("github", "code", &req.state, &req.state).await;
        assert!(matches!(result, Err(OAuthFlowError::InvalidState)));

        // No verifier or code went to github's token endpoint, no identity was
        // linked, and the state is spent: it cannot be retried on google either.
        assert!(f.http_client.seen_verifiers.lock().unwrap().is_empty());
        assert_eq!(f.linked_email("github", "sub-123").await.unwrap(), None);
        let retry = f.complete("google", "code", &req.state, &req.state).await;
        assert!(matches!(retry, Err(OAuthFlowError::InvalidState)));
    }

    #[tokio::test]
    async fn rejected_callback_never_reaches_the_token_endpoint() {
        let f = flow("user@example.com");
        let req = f.begin("google").await.unwrap();
        let result = f
            .complete("google", "code", &req.state, "attacker-cookie")
            .await;
        assert!(matches!(result, Err(OAuthFlowError::InvalidState)));
        assert!(f.http_client.seen_verifiers.lock().unwrap().is_empty());
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
        let identity = f
            .complete("google", "auth-code", &req.state, &req.state)
            .await
            .unwrap();
        let expected = Email::try_from(Secret::new("user@example.com".to_string())).unwrap();
        assert_eq!(identity.email(), &expected);

        // Verifying is not linking: the caller secures the account first.
        assert!(!identity.already_linked());
        assert_eq!(f.linked_email("google", "sub-123").await.unwrap(), None);
        assert!(!f.has_linked_identity(&expected).await.unwrap());

        f.link(&identity).await.unwrap();
        let linked = f.linked_email("google", "sub-123").await.unwrap();
        assert_eq!(linked, Some(expected.clone()));
        assert!(f.has_linked_identity(&expected).await.unwrap());

        // The next login with the same identity reports it as linked.
        let req = f.begin("google").await.unwrap();
        let again = f
            .complete("google", "auth-code", &req.state, &req.state)
            .await
            .unwrap();
        assert!(again.already_linked());
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

    #[tokio::test]
    async fn unverified_provider_email_is_rejected() {
        let f = OAuthFlow::new(
            HashMapOAuthStateStore::new(),
            HashMapOAuthIdentityStore::new(),
            MockClient::new("sub-1", "victim@example.com", false),
        )
        .with_provider(provider());

        let req = f.begin("google").await.unwrap();
        let result = f.complete("google", "code", &req.state, &req.state).await;
        assert!(matches!(result, Err(OAuthFlowError::EmailNotVerified)));
    }

    #[tokio::test]
    async fn relinking_identity_to_a_different_email_is_rejected() {
        let identity_store = HashMapOAuthIdentityStore::new();

        let link = |email: &'static str| {
            OAuthFlow::new(
                HashMapOAuthStateStore::new(),
                identity_store.clone(),
                MockClient::new("sub-123", email, true),
            )
            .with_provider(provider())
        };

        // First sign-in links (google, sub-123) -> a@.
        let f1 = link("a@example.com");
        let r1 = f1.begin("google").await.unwrap();
        let first = f1
            .complete("google", "code", &r1.state, &r1.state)
            .await
            .unwrap();
        f1.link(&first).await.unwrap();

        // The same provider identity now returning a different email must not
        // silently re-bind the account.
        let f2 = link("b@example.com");
        let r2 = f2.begin("google").await.unwrap();
        let result = f2.complete("google", "code", &r2.state, &r2.state).await;
        assert!(matches!(result, Err(OAuthFlowError::IdentityConflict)));
    }
}
