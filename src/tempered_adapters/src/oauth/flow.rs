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

use std::{collections::HashMap, sync::Arc};

use rand::RngCore;
use secrecy::{ExposeSecret, Secret};
use tempered_core::{
    ClassifyError, Email, ErrorCategory, OAuthHttpClient, OAuthIdentityStore,
    OAuthIdentityStoreError, OAuthProviderConfig, OAuthStateStore, OAuthUserInfo,
    PendingAuthorization, UserError, constant_time_eq,
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
    vouches_for_email: bool,
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

    /// Whether the provider vouches for [`email`](Self::email) right now: it
    /// reported that very address, verified. Always true for a first link.
    /// A linked identity whose address changed at the provider still logs
    /// in to its account, but no longer proves that account's address.
    pub fn vouches_for_email(&self) -> bool {
        self.vouches_for_email
    }
}

/// `Ok` for an `https` URL, or `http` on the loopback (local development).
fn check_endpoint(value: &str) -> Result<(), String> {
    let url = url::Url::parse(value).map_err(|e| format!("is not a valid URL ({e})"))?;
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback(&url) => Ok(()),
        scheme => Err(format!(
            "must use https (got {scheme}://; plain http is allowed only for localhost)"
        )),
    }
}

fn is_loopback(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => host == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

#[derive(Clone)]
pub struct OAuthFlow<ST, ID, HC> {
    state_store: ST,
    identity_store: ID,
    http_client: HC,
    /// Shared, so cloning the flow (with the scheme, per request) copies a
    /// pointer rather than every provider's settings.
    providers: Arc<HashMap<String, OAuthProviderConfig>>,
    /// OIDC signing keys, fetched on demand and shared by every login.
    keys: Arc<super::id_token::KeyCache>,
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
            providers: Arc::new(HashMap::new()),
            keys: Arc::default(),
        }
    }

    /// Register a provider; keyed by `config.name`.
    ///
    /// # Panics
    ///
    /// If an endpoint or the redirect URI is not a valid URL, or is plain
    /// `http` on a host other than the loopback (`localhost`, `127.0.0.1`,
    /// `[::1]`). The token request carries the client secret and the PKCE
    /// verifier, and the userinfo reply decides whose account is logged
    /// into, so neither may travel unencrypted. This is a configuration
    /// error, caught at startup.
    pub fn with_provider(mut self, config: OAuthProviderConfig) -> Self {
        let oidc = config.oidc.as_ref();
        for (field, value) in [
            ("auth_url", Some(&config.auth_url)),
            ("token_url", Some(&config.token_url)),
            ("userinfo_url", Some(&config.userinfo_url)),
            ("redirect_uri", Some(&config.redirect_uri)),
            ("emails_url", config.emails_url.as_ref()),
            ("oidc.issuer", oidc.map(|o| &o.issuer)),
            ("oidc.jwks_uri", oidc.map(|o| &o.jwks_uri)),
        ] {
            if let Some(value) = value
                && let Err(problem) = check_endpoint(value)
            {
                panic!("OAuth provider {:?}: {field} {problem}", config.name);
            }
        }
        if oidc.is_some() && !config.scopes.iter().any(|s| s == "openid") {
            panic!(
                "OAuth provider {:?}: OIDC needs the `openid` scope",
                config.name
            );
        }
        Arc::make_mut(&mut self.providers).insert(config.name.clone(), config);
        self
    }

    /// Step 1: build the provider authorize URL and persist the anti-CSRF state
    /// together with a fresh PKCE verifier.
    ///
    /// The returned [`AuthorizationRequest::state`] must be bound to the
    /// initiating browser (see that type's docs) and presented back to
    /// [`complete`](Self::complete).
    #[tracing::instrument(name = "OAuthFlow::begin", skip(self))]
    pub async fn begin(&self, provider: &str) -> Result<AuthorizationRequest, OAuthFlowError> {
        self.begin_inner(provider, None).await
    }

    /// Step 1 of linking `provider` to the logged-in account `account`: like
    /// [`begin`](Self::begin), with the account recorded in the pending
    /// request. Finish with [`complete_link`](Self::complete_link).
    pub async fn begin_link(
        &self,
        provider: &str,
        account: Email,
    ) -> Result<AuthorizationRequest, OAuthFlowError> {
        self.begin_inner(provider, Some(account)).await
    }

    async fn begin_inner(
        &self,
        provider: &str,
        link_to: Option<Email>,
    ) -> Result<AuthorizationRequest, OAuthFlowError> {
        let config = self.provider(provider)?;
        let state = random_state();
        let code_verifier = generate_verifier();
        // Only the challenge travels through the browser; the verifier stays here.
        let code_challenge = pkce_challenge_s256(code_verifier.expose_secret());
        let nonce = config.oidc.as_ref().map(|_| Secret::new(random_state()));
        let authorize_url = build_authorize_url(
            config,
            &state,
            &code_challenge,
            nonce.as_ref().map(|n| n.expose_secret().as_str()),
        );
        self.state_store
            .store_state(
                state.clone(),
                PendingAuthorization {
                    provider: config.name.clone(),
                    code_verifier,
                    nonce,
                    link_to,
                },
            )
            .await
            .map_err(|e| OAuthFlowError::State(e.to_string()))?;
        Ok(AuthorizationRequest {
            authorize_url,
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
    async fn redeem_callback(
        &self,
        provider: &str,
        code: &str,
        query_state: &str,
        cookie_state: &str,
    ) -> Result<(Option<Email>, OAuthUserInfo), OAuthFlowError> {
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

        let tokens = self
            .http_client
            .exchange_code(config, code, code_verifier.expose_secret())
            .await?;
        let info = match &config.oidc {
            Some(oidc) => {
                self.identity_from_id_token(config, oidc, &tokens, pending.nonce)
                    .await?
            }
            None => {
                self.http_client
                    .fetch_user_info(config, tokens.access_token.expose_secret())
                    .await?
            }
        };
        Ok((pending.link_to, info))
    }

    #[tracing::instrument(name = "OAuthFlow::complete", skip_all, fields(provider = provider))]
    pub async fn complete(
        &self,
        provider: &str,
        code: &str,
        query_state: &str,
        cookie_state: &str,
    ) -> Result<VerifiedIdentity, OAuthFlowError> {
        let (link_to, info) = self
            .redeem_callback(provider, code, query_state, cookie_state)
            .await?;
        // A link request finishes only as a link.
        if link_to.is_some() {
            return Err(OAuthFlowError::InvalidState);
        }

        // A linked identity is the provider's `subject`, which is stable;
        // the email is not (OIDC Core §5.7: do not key on it). So a linked
        // identity logs in to the account it was linked to, even after the
        // address changed at the provider. The link is never moved to the new
        // address, and whatever account that address may have is not touched.
        if let Some(linked) = self.linked_email(provider, &info.subject).await? {
            let reported = Email::try_from(Secret::new(info.email)).ok();
            return Ok(VerifiedIdentity {
                provider: provider.to_string(),
                subject: info.subject,
                vouches_for_email: info.email_verified && reported.as_ref() == Some(&linked),
                email: linked,
                already_linked: true,
            });
        }

        // A first link does go by the email, so it must be verified: an
        // attacker could otherwise register a victim's address (unverified)
        // at the provider and take over the local account.
        if !info.email_verified {
            return Err(OAuthFlowError::EmailNotVerified);
        }
        let email = Email::try_from(Secret::new(info.email))?;
        Ok(VerifiedIdentity {
            provider: provider.to_string(),
            subject: info.subject,
            email,
            already_linked: false,
            vouches_for_email: true,
        })
    }

    /// The identity an OIDC login proves: the ID token's, checked against
    /// the provider's keys, our client id and this login's nonce. When the
    /// token carries no address, the userinfo endpoint supplies it, and must
    /// describe the same subject.
    async fn identity_from_id_token(
        &self,
        config: &OAuthProviderConfig,
        oidc: &tempered_core::OidcSettings,
        tokens: &tempered_core::TokenResponse,
        nonce: Option<Secret<String>>,
    ) -> Result<OAuthUserInfo, OAuthFlowError> {
        let refused = |why: String| OAuthFlowError::IdToken(why);
        let token = tokens
            .id_token
            .as_deref()
            .ok_or_else(|| refused("the token response has no id_token".to_string()))?;
        let nonce = nonce.ok_or_else(|| refused("this login sent no nonce".to_string()))?;
        let claims = self
            .keys
            .verify(
                &self.http_client,
                oidc,
                &config.client_id,
                token,
                nonce.expose_secret(),
            )
            .await
            .map_err(refused)?;
        if let Some(email) = claims.email {
            return Ok(OAuthUserInfo {
                subject: claims.subject,
                email,
                email_verified: claims.email_verified,
            });
        }
        let info = self
            .http_client
            .fetch_user_info(config, tokens.access_token.expose_secret())
            .await?;
        if !constant_time_eq(&info.subject, &claims.subject) {
            return Err(refused("userinfo describes another subject".to_string()));
        }
        Ok(info)
    }

    /// Step 2 of linking: the identity the provider proves, for the account
    /// the link was begun for (whatever address the provider reports). A
    /// login request does not finish here, and an identity linked to another
    /// account is refused.
    #[tracing::instrument(name = "OAuthFlow::complete_link", skip_all, fields(provider = provider))]
    pub async fn complete_link(
        &self,
        provider: &str,
        code: &str,
        query_state: &str,
        cookie_state: &str,
    ) -> Result<VerifiedIdentity, OAuthFlowError> {
        let (link_to, info) = self
            .redeem_callback(provider, code, query_state, cookie_state)
            .await?;
        let Some(account) = link_to else {
            return Err(OAuthFlowError::InvalidState);
        };
        let linked = self.linked_email(provider, &info.subject).await?;
        if linked.as_ref().is_some_and(|e| e != &account) {
            return Err(OAuthFlowError::IdentityConflict);
        }
        let reported = Email::try_from(Secret::new(info.email)).ok();
        Ok(VerifiedIdentity {
            provider: provider.to_string(),
            subject: info.subject,
            vouches_for_email: info.email_verified && reported.as_ref() == Some(&account),
            email: account,
            already_linked: linked.is_some(),
        })
    }

    /// The providers linked to `email`.
    pub async fn links(&self, email: &Email) -> Result<Vec<String>, OAuthFlowError> {
        let mut providers: Vec<String> = self
            .identity_store
            .list_for_user(email)
            .await
            .map_err(|e| OAuthFlowError::Identity(e.to_string()))?
            .into_iter()
            .map(|(provider, _)| provider)
            .collect();
        providers.dedup();
        Ok(providers)
    }

    /// Remove `email`'s link to `provider`.
    pub async fn unlink(&self, email: &Email, provider: &str) -> Result<bool, OAuthFlowError> {
        self.identity_store
            .unlink(email, provider)
            .await
            .map_err(|e| OAuthFlowError::Identity(e.to_string()))
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

    /// Whether `identity` is linked to its account right now.
    pub async fn is_linked(&self, identity: &VerifiedIdentity) -> Result<bool, OAuthFlowError> {
        Ok(self
            .linked_email(&identity.provider, &identity.subject)
            .await?
            .as_ref()
            == Some(&identity.email))
    }

    /// Whether any provider identity is already linked to `email`'s account.
    pub async fn has_linked_identity(&self, email: &Email) -> Result<bool, OAuthFlowError> {
        self.identity_store
            .has_identity_for_email(email)
            .await
            .map_err(|e| OAuthFlowError::Identity(e.to_string()))
    }

    /// Remove every provider identity linked to `email`'s account. Call when
    /// the account is deleted, so its links cannot log anyone in to, or stand
    /// as proof for, a later account that reuses the address.
    pub async fn forget_user(&self, email: &Email) -> Result<(), OAuthFlowError> {
        self.identity_store
            .unlink_all_for_email(email)
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

fn build_authorize_url(
    config: &OAuthProviderConfig,
    state: &str,
    code_challenge: &str,
    nonce: Option<&str>,
) -> String {
    // Checked when the provider was registered (`with_provider`).
    let mut url = url::Url::parse(&config.auth_url).expect("provider auth_url must be a valid URL");
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", &config.redirect_uri)
        .append_pair("scope", &config.scopes.join(" "))
        .append_pair("state", state)
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", CODE_CHALLENGE_METHOD);
    if let Some(nonce) = nonce {
        url.query_pairs_mut().append_pair("nonce", nonce);
    }
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
    #[error("ID token refused: {0}")]
    IdToken(String),
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
            // Why the token failed is for the log: it can show what a forger
            // got right.
            OAuthFlowError::IdToken(why) => {
                tracing::warn!(reason = %why, "OIDC ID token refused");
                (
                    ErrorCategory::Unauthorized,
                    "The login with the provider could not be verified".to_string(),
                )
            }
            e @ (OAuthFlowError::State(_) | OAuthFlowError::Identity(_)) => {
                tracing::error!(error = %e, "OAuth store error");
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
        async fn fetch_json(&self, _: &str) -> Result<serde_json::Value, OAuthHttpError> {
            unreachable!("plain OAuth2 in these tests")
        }

        async fn exchange_code(
            &self,
            _config: &OAuthProviderConfig,
            _code: &str,
            code_verifier: &str,
        ) -> Result<tempered_core::TokenResponse, OAuthHttpError> {
            self.seen_verifiers
                .lock()
                .unwrap()
                .push(code_verifier.to_string());
            Ok(tempered_core::TokenResponse {
                access_token: secrecy::Secret::new("access-token".to_string()),
                id_token: None,
            })
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

    #[test]
    fn provider_endpoints_must_be_https_except_on_the_loopback() {
        for ok in [
            "https://accounts.example.com/token",
            "http://localhost:3000/mock/token",
            "http://127.0.0.1:8080/token",
            "http://[::1]:8080/token",
        ] {
            assert!(check_endpoint(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://accounts.example.com/token",
            "ftp://accounts.example.com/token",
            "not a url",
            "http://localhost.evil.example/token",
        ] {
            assert!(check_endpoint(bad).is_err(), "{bad}");
        }
    }

    #[test]
    #[should_panic(expected = "token_url must use https")]
    fn a_plain_http_token_endpoint_is_refused_at_startup() {
        let mut config = provider();
        config.token_url = "http://accounts.example.com/token".to_string();
        let _ = OAuthFlow::new(
            HashMapOAuthStateStore::new(),
            HashMapOAuthIdentityStore::new(),
            MockClient::new("sub", "user@example.com", true),
        )
        .with_provider(config);
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
            oidc: None,
            emails_url: None,
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
    async fn a_linked_identity_keeps_its_account_when_the_provider_email_changes() {
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

        // The same provider identity now reports another address. It logs in
        // to the account it is linked to: the link is not moved to b@ (whose
        // account, if any, it never reaches), and the user is not locked out.
        let f2 = link("b@example.com");
        let r2 = f2.begin("google").await.unwrap();
        let second = f2
            .complete("google", "code", &r2.state, &r2.state)
            .await
            .unwrap();
        assert_eq!(second.email(), first.email());
        assert!(second.already_linked());
        // But the provider no longer vouches for a@.
        assert!(first.vouches_for_email());
        assert!(!second.vouches_for_email());
    }

    #[tokio::test]
    async fn a_linked_identity_logs_in_even_if_its_new_address_is_unverified() {
        let identity_store = HashMapOAuthIdentityStore::new();
        let flow = |email: &'static str, verified| {
            OAuthFlow::new(
                HashMapOAuthStateStore::new(),
                identity_store.clone(),
                MockClient::new("sub-123", email, verified),
            )
            .with_provider(provider())
        };
        let f1 = flow("a@example.com", true);
        let r1 = f1.begin("google").await.unwrap();
        let first = f1
            .complete("google", "code", &r1.state, &r1.state)
            .await
            .unwrap();
        f1.link(&first).await.unwrap();

        // The address is not what identifies the user, so its state does not
        // matter once the identity is linked.
        let f2 = flow("new-unconfirmed@example.com", false);
        let r2 = f2.begin("google").await.unwrap();
        let second = f2
            .complete("google", "code", &r2.state, &r2.state)
            .await
            .unwrap();
        assert_eq!(second.email(), first.email());
        assert!(!second.vouches_for_email());
    }
}

/// OIDC: ID tokens signed with a test key, served as a JWKS by a mock
/// provider.
#[cfg(test)]
mod oidc_tests {
    use super::*;
    use crate::persistence::hashmap_oauth_identity_store::HashMapOAuthIdentityStore;
    use crate::persistence::hashmap_oauth_state_store::HashMapOAuthStateStore;
    use async_trait::async_trait;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use tempered_core::{OAuthHttpError, OidcSettings, TokenResponse};

    /// A throwaway Ed25519 key, used only here.
    const KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIA2ZLlv7Fjn0b25zMCmAD3a/yfAHP1vNguNqqoum5wdH
-----END PRIVATE KEY-----";
    const KEY_X: &str = "W3DI0L_-8PhUTwOqJ8wc9wfMSEhDyL_lzkuukXRdD-Q";
    const ISSUER: &str = "https://id.example.com";
    const CLIENT: &str = "client-123";

    #[derive(Clone, Default)]
    struct Provider {
        id_token: Arc<Mutex<Option<String>>>,
        userinfo: Arc<Mutex<Option<OAuthUserInfo>>>,
        key_fetches: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl OAuthHttpClient for Provider {
        async fn exchange_code(
            &self,
            _: &OAuthProviderConfig,
            _: &str,
            _: &str,
        ) -> Result<TokenResponse, OAuthHttpError> {
            Ok(TokenResponse {
                access_token: Secret::new("access".to_string()),
                id_token: self.id_token.lock().unwrap().clone(),
            })
        }
        async fn fetch_user_info(
            &self,
            _: &OAuthProviderConfig,
            _: &str,
        ) -> Result<OAuthUserInfo, OAuthHttpError> {
            self.userinfo
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| OAuthHttpError::UserInfo("not expected".into()))
        }
        async fn fetch_json(&self, url: &str) -> Result<serde_json::Value, OAuthHttpError> {
            assert_eq!(url, "https://id.example.com/keys");
            self.key_fetches.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::json!({ "keys": [{
                "kty": "OKP", "crv": "Ed25519", "x": KEY_X, "kid": "k1", "alg": "EdDSA", "use": "sig"
            }]}))
        }
    }

    type Flow = OAuthFlow<HashMapOAuthStateStore, HashMapOAuthIdentityStore, Provider>;

    fn flow(provider: Provider) -> Flow {
        OAuthFlow::new(
            HashMapOAuthStateStore::new(),
            HashMapOAuthIdentityStore::new(),
            provider,
        )
        .with_provider(OAuthProviderConfig {
            name: "id".to_string(),
            client_id: CLIENT.to_string(),
            client_secret: Secret::new("secret".to_string()),
            auth_url: "https://id.example.com/authorize".to_string(),
            token_url: "https://id.example.com/token".to_string(),
            userinfo_url: "https://id.example.com/userinfo".to_string(),
            redirect_uri: "https://app.example.com/oauth/id/callback".to_string(),
            scopes: vec!["openid".to_string(), "email".to_string()],
            oidc: Some(OidcSettings {
                issuer: ISSUER.to_string(),
                jwks_uri: "https://id.example.com/keys".to_string(),
            }),
            emails_url: None,
        })
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    /// Claims for a good token answering `nonce`; tests break one at a time.
    fn claims(nonce: &str) -> serde_json::Value {
        serde_json::json!({
            "iss": ISSUER, "aud": CLIENT, "sub": "user-1", "nonce": nonce,
            "exp": now() + 300, "iat": now(),
            "email": "a@example.com", "email_verified": true,
        })
    }

    fn sign(claims: &serde_json::Value, kid: &str) -> String {
        let mut header = Header::new(jsonwebtoken::Algorithm::EdDSA);
        header.kid = Some(kid.to_string());
        // The PEM's body is the PKCS#8 DER.
        let der: String = KEY_PEM
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, der).unwrap();
        encode(&header, claims, &EncodingKey::from_ed_der(&der)).unwrap()
    }

    /// Begin a login; the state and the nonce the authorize URL carries.
    async fn begin(flow: &Flow) -> (String, String) {
        let request = flow.begin("id").await.unwrap();
        let url = url::Url::parse(&request.authorize_url).unwrap();
        let nonce = url
            .query_pairs()
            .find(|(k, _)| k == "nonce")
            .map(|(_, v)| v.to_string())
            .expect("an OIDC login sends a nonce");
        (request.state, nonce)
    }

    /// Run one login whose provider answers with `token(nonce)`.
    async fn login_with(
        provider: Provider,
        token: impl FnOnce(&str) -> String,
    ) -> Result<VerifiedIdentity, OAuthFlowError> {
        let flow = flow(provider.clone());
        let (state, nonce) = begin(&flow).await;
        *provider.id_token.lock().unwrap() = Some(token(&nonce));
        flow.complete("id", "code", &state, &state).await
    }

    #[tokio::test]
    async fn a_valid_id_token_decides_the_identity() {
        let identity = login_with(Provider::default(), |n| sign(&claims(n), "k1"))
            .await
            .unwrap();
        assert_eq!(identity.subject, "user-1");
        assert_eq!(identity.email().as_ref().expose_secret(), "a@example.com");
    }

    #[tokio::test]
    async fn a_broken_id_token_is_refused() {
        type MakeToken = Box<dyn Fn(&str) -> String>;
        let cases: Vec<(&str, MakeToken)> = vec![
            (
                "another login's nonce",
                Box::new(|_| sign(&claims("not-this-one"), "k1")),
            ),
            (
                "another client",
                Box::new(|n| {
                    sign(
                        &{
                            let mut c = claims(n);
                            c["aud"] = "someone-else".into();
                            c
                        },
                        "k1",
                    )
                }),
            ),
            (
                "another issuer",
                Box::new(|n| {
                    sign(
                        &{
                            let mut c = claims(n);
                            c["iss"] = "https://evil.example".into();
                            c
                        },
                        "k1",
                    )
                }),
            ),
            (
                "expired",
                Box::new(|n| {
                    sign(
                        &{
                            let mut c = claims(n);
                            c["exp"] = (now() - 3600).into();
                            c
                        },
                        "k1",
                    )
                }),
            ),
            (
                "issued to another party",
                Box::new(|n| {
                    sign(
                        &{
                            let mut c = claims(n);
                            c["aud"] = serde_json::json!([CLIENT, "other"]);
                            c
                        },
                        "k1",
                    )
                }),
            ),
            ("unknown key", Box::new(|n| sign(&claims(n), "k2"))),
            (
                "no signature",
                Box::new(|n| {
                    let header = base64::Engine::encode(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                        r#"{"alg":"none","kid":"k1"}"#,
                    );
                    let body = base64::Engine::encode(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                        claims(n).to_string(),
                    );
                    format!("{header}.{body}.")
                }),
            ),
            (
                "HMAC",
                Box::new(|n| {
                    let mut header = Header::new(jsonwebtoken::Algorithm::HS256);
                    header.kid = Some("k1".into());
                    encode(
                        &header,
                        &claims(n),
                        &EncodingKey::from_secret(KEY_X.as_bytes()),
                    )
                    .unwrap()
                }),
            ),
        ];
        for (case, token) in cases {
            let result = login_with(Provider::default(), token).await;
            assert!(
                matches!(result, Err(OAuthFlowError::IdToken(_))),
                "{case}: {:?}",
                result.map(|i| i.subject)
            );
        }
        // And a provider that sends no ID token at all.
        let flow = flow(Provider::default());
        let (state, _) = begin(&flow).await;
        assert!(matches!(
            flow.complete("id", "code", &state, &state).await,
            Err(OAuthFlowError::IdToken(_))
        ));
    }

    #[tokio::test]
    async fn keys_are_fetched_once_and_an_unknown_kid_does_not_refetch_at_once() {
        let provider = Provider::default();
        let flow = flow(provider.clone());
        for _ in 0..3 {
            let (state, nonce) = begin(&flow).await;
            *provider.id_token.lock().unwrap() = Some(sign(&claims(&nonce), "k1"));
            flow.complete("id", "code", &state, &state).await.unwrap();
        }
        assert_eq!(provider.key_fetches.load(Ordering::SeqCst), 1);
        let (state, nonce) = begin(&flow).await;
        *provider.id_token.lock().unwrap() = Some(sign(&claims(&nonce), "rotated"));
        assert!(flow.complete("id", "code", &state, &state).await.is_err());
        assert_eq!(
            provider.key_fetches.load(Ordering::SeqCst),
            1,
            "no refetch within a minute"
        );
    }

    #[tokio::test]
    async fn without_an_email_claim_userinfo_must_describe_the_same_subject() {
        let no_email = |n: &str| {
            let mut c = claims(n);
            c.as_object_mut().unwrap().remove("email");
            sign(&c, "k1")
        };
        let provider = Provider::default();
        *provider.userinfo.lock().unwrap() = Some(OAuthUserInfo {
            subject: "user-1".into(),
            email: "a@example.com".into(),
            email_verified: true,
        });
        assert!(login_with(provider, no_email).await.is_ok());

        let provider = Provider::default();
        *provider.userinfo.lock().unwrap() = Some(OAuthUserInfo {
            subject: "someone-else".into(),
            email: "victim@example.com".into(),
            email_verified: true,
        });
        assert!(matches!(
            login_with(provider, no_email).await,
            Err(OAuthFlowError::IdToken(_))
        ));
    }

    #[test]
    #[should_panic(expected = "OIDC needs the `openid` scope")]
    fn oidc_without_the_openid_scope_is_refused_at_startup() {
        let mut config = flow(Provider::default()).provider("id").unwrap().clone();
        config.scopes = vec!["email".to_string()];
        let _ = OAuthFlow::new(
            HashMapOAuthStateStore::new(),
            HashMapOAuthIdentityStore::new(),
            Provider::default(),
        )
        .with_provider(config);
    }
}
