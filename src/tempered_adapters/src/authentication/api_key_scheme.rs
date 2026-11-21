//! API key authentication scheme (machine-to-machine).
//!
//! Unlike password schemes, keys are *issued* to an existing owner (see
//! [`SupportsApiKeyIssuance`]) and presented on each request via a header
//! (`x-api-key` by default, or `Authorization: Bearer <key>`). The real
//! enforcement path is the [`ApiKeyValidator`] used by middleware; the `login`
//! endpoint is a convenience that simply verifies a presented key.
//!
//! A key looks like `"{prefix}.{secret}"`. Only the SHA-256 hash of `secret` is
//! stored; the `prefix` is a non-secret O(1) lookup handle. SHA-256 (not Argon2)
//! is appropriate here because keys are high-entropy random values, and
//! validation happens on every request.
//!
//! Like [`JwtScheme`](crate::authentication::jwt_scheme::JwtScheme), the scheme
//! is built with a **type-state builder**. Validation is the mandatory core;
//! *issuance* (minting/revoking/listing keys) is opt-in via
//! [`ApiKeyScheme::supports_issuance`], which fills a generic slot that defaults
//! to `()` = disabled. A service that only *checks* keys minted by a central
//! issuer therefore never gains — or exposes — the issuance API.

use async_trait::async_trait;
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tempered_core::{
    ApiKeyId, ApiKeyMetadata, ApiKeyRecord, ApiKeyStore, ApiKeyStoreError, AuthRequest,
    AuthValidator, AuthenticationScheme, ClassifyError, Email, ErrorCategory,
    HttpAuthenticationScheme, HttpResponseBuilderExt, LoginOutcome, ResponseBuilder,
    ResponseBuilderError, SupportsApiKeyIssuance, constant_time_eq,
    domain::api_key::split_presented_key,
};
use thiserror::Error;

// ============================================================================
// Scheme
// ============================================================================

/// API key authentication scheme.
///
/// The generic slot `I` defaults to `()` (issuance disabled). Calling
/// [`supports_issuance`](ApiKeyScheme::supports_issuance) swaps it for the
/// [`Issuance`] marker, which is the only state in which
/// [`SupportsApiKeyIssuance`] is implemented.
#[derive(Clone)]
pub struct ApiKeyScheme<S, I = ()> {
    store: S,
    header_name: String,
    validator: ApiKeyValidator<S>,
    // Pure type-state marker: never read at runtime — its *type* (`()` vs
    // `Issuance`) is what selects whether `SupportsApiKeyIssuance` is implemented.
    #[allow(dead_code)]
    issuance: I,
}

/// Enabled issuance slot. Carries no data — issuance only needs the store, which
/// the scheme already holds — so it is a zero-sized marker.
#[derive(Clone, Copy, Debug, Default)]
pub struct Issuance;

impl<S> ApiKeyScheme<S, ()>
where
    S: ApiKeyStore + Clone,
{
    /// Create a validate-only scheme that reads keys from the `x-api-key` header.
    ///
    /// Opt into key issuance with [`supports_issuance`](ApiKeyScheme::supports_issuance).
    pub fn new(store: S) -> Self {
        Self::with_header(store, "x-api-key")
    }

    /// Create a validate-only scheme that reads keys from a custom header (falls
    /// back to `Authorization: Bearer` regardless).
    pub fn with_header(store: S, header_name: impl Into<String>) -> Self {
        let header_name = header_name.into();
        let validator = ApiKeyValidator::new(store.clone(), header_name.clone());
        Self {
            store,
            header_name,
            validator,
            issuance: (),
        }
    }
}

impl<S, I> ApiKeyScheme<S, I> {
    /// Enable key issuance, lighting up [`SupportsApiKeyIssuance`] (mint, revoke,
    /// and list keys). Leave it off for services that only validate keys minted
    /// elsewhere.
    pub fn supports_issuance(self) -> ApiKeyScheme<S, Issuance> {
        ApiKeyScheme {
            store: self.store,
            header_name: self.header_name,
            validator: self.validator,
            issuance: Issuance,
        }
    }

    /// Finalizer for readability; the scheme is already usable. Returns `self`.
    pub fn build(self) -> Self {
        self
    }
}

// ============================================================================
// Wire types
// ============================================================================

/// The raw key as presented by the client (validated by the `Validator`).
#[derive(Clone, Debug)]
pub struct ApiKeyToken(pub String);

#[derive(Debug, Deserialize)]
pub struct ApiKeyCredentials {
    pub api_key: String,
}

// ============================================================================
// Hashing / generation helpers
// ============================================================================

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hash_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hex(&hasher.finalize())
}

fn generate_key() -> (String, String) {
    let mut prefix = [0u8; 6];
    let mut secret = [0u8; 24];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut prefix);
    rng.fill_bytes(&mut secret);
    (hex(&prefix), hex(&secret))
}

/// Verify a presented `"prefix.secret"` key against the store and return claims.
async fn validate_presented_key<S: ApiKeyStore>(
    store: &S,
    presented: &str,
) -> Result<ApiKeyClaims, ApiKeyAuthError> {
    let (prefix, secret) = split_presented_key(presented).ok_or(ApiKeyAuthError::Malformed)?;

    let record = store.find_by_prefix(prefix).await.map_err(store_err)?;

    if !constant_time_eq(&hash_secret(secret), &record.secret_hash) {
        return Err(ApiKeyAuthError::InvalidKey);
    }

    Ok(ApiKeyClaims {
        id: record.id,
        owner: record.owner,
        scopes: record.scopes,
    })
}

fn extract_from_headers(headers: &http::HeaderMap, header_name: &str) -> Option<String> {
    if let Some(v) = headers.get(header_name).and_then(|v| v.to_str().ok())
        && !v.is_empty()
    {
        return Some(v.to_string());
    }
    let auth = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    auth.strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))
        .map(|k| k.to_string())
}

// ============================================================================
// Core trait: AuthenticationScheme
// ============================================================================

#[async_trait]
impl<S, I> AuthenticationScheme for ApiKeyScheme<S, I>
where
    S: ApiKeyStore + Clone + Send + Sync + 'static,
    I: Clone + Send + Sync + 'static,
{
    type Token = ApiKeyToken;
    type LogoutOutput = String;
    type Validator = ApiKeyValidator<S>;
    type Credentials = ApiKeyCredentials;
    type AuthError = ApiKeyAuthError;

    #[tracing::instrument(name = "ApiKeyScheme::login", skip(self, credentials))]
    async fn login(
        &self,
        credentials: Self::Credentials,
    ) -> Result<LoginOutcome<Self::Token>, Self::AuthError> {
        // Verify the presented key; the token is the key itself.
        validate_presented_key(&self.store, &credentials.api_key).await?;
        Ok(LoginOutcome::Success(ApiKeyToken(credentials.api_key)))
    }

    async fn logout(&self, _token: &Self::Token) -> Result<Self::LogoutOutput, Self::AuthError> {
        Ok("API keys are revoked via the issuance API, not logged out".to_string())
    }

    fn validator(&self) -> &Self::Validator {
        &self.validator
    }
}

// ============================================================================
// HTTP delivery (no cookie — keys live in headers)
// ============================================================================

impl<S, I> HttpAuthenticationScheme for ApiKeyScheme<S, I>
where
    S: ApiKeyStore + Clone + Send + Sync + 'static,
    I: Clone + Send + Sync + 'static,
{
    fn create_login_response<RB: ResponseBuilder>(
        &self,
        builder: RB,
        outcome: LoginOutcome<Self::Token>,
    ) -> Result<RB::Response, ResponseBuilderError> {
        match outcome {
            LoginOutcome::Success(_) => builder
                .status(200)
                .json_body(serde_json::json!({ "status": "success", "message": "API key valid" }))
                .build(),
            LoginOutcome::Requires2Fa { .. } => builder
                .status(206)
                .json_body(serde_json::json!({ "status": "requires_2fa" }))
                .build(),
        }
    }

    fn create_logout_response<RB: ResponseBuilder>(
        &self,
        builder: RB,
        _cookie_name: Option<String>,
    ) -> Result<RB::Response, ResponseBuilderError> {
        builder
            .status(200)
            .json_body(serde_json::json!({ "message": "API keys are revoked, not logged out" }))
            .build()
    }

    fn extract_token_from_request<Req: AuthRequest>(&self, req: &Req) -> Option<Self::Token> {
        if let Some(v) = req.header(&self.header_name)
            && !v.is_empty()
        {
            return Some(ApiKeyToken(v.to_string()));
        }
        let auth = req.header("authorization")?;
        auth.strip_prefix("Bearer ")
            .or_else(|| auth.strip_prefix("bearer "))
            .map(|k| ApiKeyToken(k.to_string()))
    }
}

// ============================================================================
// Issuance capability
// ============================================================================

#[async_trait]
impl<S> SupportsApiKeyIssuance for ApiKeyScheme<S, Issuance>
where
    S: ApiKeyStore + Clone + Send + Sync + 'static,
{
    type IssuanceError = ApiKeyAuthError;

    #[tracing::instrument(name = "ApiKeyScheme::issue_api_key", skip(self))]
    async fn issue_api_key(
        &self,
        owner: Email,
        scopes: Vec<String>,
    ) -> Result<(ApiKeyId, String), Self::IssuanceError> {
        // A 48-bit prefix clashes rarely, but the store refuses a clash
        // rather than overwrite another key, so draw again.
        for _ in 0..ISSUE_ATTEMPTS {
            let (prefix, secret) = generate_key();
            let id = ApiKeyId::new();
            let record = ApiKeyRecord {
                id: id.clone(),
                prefix: prefix.clone(),
                secret_hash: hash_secret(&secret),
                owner: owner.clone(),
                scopes: scopes.clone(),
            };
            match self.store.create_key(record).await {
                Ok(()) => return Ok((id, format!("{}.{}", prefix, secret))),
                Err(ApiKeyStoreError::PrefixTaken) => continue,
                Err(e) => return Err(store_err(e)),
            }
        }
        Err(ApiKeyAuthError::StoreError(
            "no free key prefix after several attempts".to_string(),
        ))
    }

    async fn revoke_api_key(
        &self,
        owner: &Email,
        id: &ApiKeyId,
    ) -> Result<(), Self::IssuanceError> {
        self.store.revoke_key(owner, id).await.map_err(store_err)
    }

    async fn revoke_all_api_keys(&self, owner: &Email) -> Result<(), Self::IssuanceError> {
        self.store
            .delete_all_for_owner(owner)
            .await
            .map_err(store_err)
    }

    async fn list_api_keys(
        &self,
        owner: &Email,
    ) -> Result<Vec<ApiKeyMetadata>, Self::IssuanceError> {
        self.store.list_for_user(owner).await.map_err(store_err)
    }
}

// ============================================================================
// Validator
// ============================================================================

#[derive(Clone, Debug)]
pub struct ApiKeyClaims {
    pub id: ApiKeyId,
    pub owner: Email,
    pub scopes: Vec<String>,
}

#[derive(Clone)]
pub struct ApiKeyValidator<S> {
    store: S,
    header_name: String,
}

impl<S> ApiKeyValidator<S> {
    pub fn new(store: S, header_name: String) -> Self {
        Self { store, header_name }
    }
}

#[async_trait]
impl<S> AuthValidator for ApiKeyValidator<S>
where
    S: ApiKeyStore + Clone + 'static,
{
    type Claims = ApiKeyClaims;
    type RequestParts = http::request::Parts;
    type Error = ApiKeyAuthError;

    async fn validate(&self, parts: &Self::RequestParts) -> Result<Self::Claims, Self::Error> {
        let presented = extract_from_headers(&parts.headers, &self.header_name)
            .ok_or(ApiKeyAuthError::MissingKey)?;
        validate_presented_key(&self.store, &presented).await
    }
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, Error)]
pub enum ApiKeyAuthError {
    #[error("Missing API key")]
    MissingKey,
    #[error("Malformed API key")]
    Malformed,
    #[error("Invalid API key")]
    InvalidKey,
    #[error("API key store error: {0}")]
    StoreError(String),
}

/// Fresh keys to draw before giving up on a free prefix.
const ISSUE_ATTEMPTS: usize = 3;

fn store_err(e: ApiKeyStoreError) -> ApiKeyAuthError {
    match e {
        ApiKeyStoreError::NotFound => ApiKeyAuthError::InvalidKey,
        e @ (ApiKeyStoreError::PrefixTaken | ApiKeyStoreError::UnexpectedError(_)) => {
            ApiKeyAuthError::StoreError(e.to_string())
        }
    }
}

impl ClassifyError for ApiKeyAuthError {
    fn classify(self) -> (ErrorCategory, String) {
        match self {
            ApiKeyAuthError::MissingKey => {
                (ErrorCategory::Unauthorized, "Missing API key".to_string())
            }
            ApiKeyAuthError::Malformed => {
                (ErrorCategory::BadRequest, "Malformed API key".to_string())
            }
            ApiKeyAuthError::InvalidKey => {
                (ErrorCategory::Unauthorized, "Invalid API key".to_string())
            }
            ApiKeyAuthError::StoreError(m) => (ErrorCategory::Internal, m),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::hashmap_api_key_store::HashMapApiKeyStore;
    use secrecy::Secret;

    fn owner() -> Email {
        Email::try_from(Secret::new("svc@example.com".to_string())).unwrap()
    }

    fn parts_with_header(name: &str, value: &str) -> http::request::Parts {
        http::Request::builder()
            .header(name, value)
            .body(())
            .unwrap()
            .into_parts()
            .0
    }

    #[tokio::test]
    async fn issued_key_validates_and_carries_owner() {
        let scheme = ApiKeyScheme::new(HashMapApiKeyStore::new()).supports_issuance();
        let (id, plaintext) = scheme
            .issue_api_key(owner(), vec!["read".to_string()])
            .await
            .unwrap();

        let parts = parts_with_header("x-api-key", &plaintext);
        let claims = scheme.validator().validate(&parts).await.unwrap();
        assert_eq!(claims.id, id);
        assert_eq!(claims.owner, owner());
        assert_eq!(claims.scopes, vec!["read".to_string()]);
    }

    #[tokio::test]
    async fn bearer_header_is_accepted() {
        let scheme = ApiKeyScheme::new(HashMapApiKeyStore::new()).supports_issuance();
        let (_, plaintext) = scheme.issue_api_key(owner(), vec![]).await.unwrap();

        let parts = parts_with_header("authorization", &format!("Bearer {}", plaintext));
        assert!(scheme.validator().validate(&parts).await.is_ok());
    }

    #[tokio::test]
    async fn wrong_secret_is_rejected() {
        let scheme = ApiKeyScheme::new(HashMapApiKeyStore::new()).supports_issuance();
        let (_, plaintext) = scheme.issue_api_key(owner(), vec![]).await.unwrap();
        let prefix = plaintext.split_once('.').unwrap().0;

        let forged = format!("{}.{}", prefix, "deadbeef".repeat(6));
        let parts = parts_with_header("x-api-key", &forged);
        assert!(matches!(
            scheme.validator().validate(&parts).await,
            Err(ApiKeyAuthError::InvalidKey)
        ));
    }

    #[tokio::test]
    async fn revoked_key_stops_validating() {
        let scheme = ApiKeyScheme::new(HashMapApiKeyStore::new()).supports_issuance();
        let (id, plaintext) = scheme.issue_api_key(owner(), vec![]).await.unwrap();

        scheme.revoke_api_key(&owner(), &id).await.unwrap();

        let parts = parts_with_header("x-api-key", &plaintext);
        assert!(scheme.validator().validate(&parts).await.is_err());
    }

    #[tokio::test]
    async fn a_key_id_alone_does_not_revoke_someone_elses_key() {
        // A handler that revoked whatever id the request named let any
        // logged-in user revoke anyone's key. The owner must match.
        let scheme = ApiKeyScheme::new(HashMapApiKeyStore::new()).supports_issuance();
        let (id, plaintext) = scheme.issue_api_key(owner(), vec![]).await.unwrap();
        let mallory = Email::try_from(Secret::new("mallory@example.com".to_string())).unwrap();

        assert!(matches!(
            scheme.revoke_api_key(&mallory, &id).await,
            Err(ApiKeyAuthError::InvalidKey)
        ));
        let parts = parts_with_header("x-api-key", &plaintext);
        assert!(scheme.validator().validate(&parts).await.is_ok());
    }

    #[tokio::test]
    async fn revoking_all_of_an_owners_keys_stops_every_one() {
        let scheme = ApiKeyScheme::new(HashMapApiKeyStore::new()).supports_issuance();
        let (_, first) = scheme.issue_api_key(owner(), vec![]).await.unwrap();
        let (_, second) = scheme.issue_api_key(owner(), vec![]).await.unwrap();

        scheme.revoke_all_api_keys(&owner()).await.unwrap();

        for key in [first, second] {
            let parts = parts_with_header("x-api-key", &key);
            assert!(scheme.validator().validate(&parts).await.is_err());
        }
        assert!(scheme.list_api_keys(&owner()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn missing_key_is_rejected() {
        let scheme = ApiKeyScheme::new(HashMapApiKeyStore::new());
        let parts = http::Request::builder().body(()).unwrap().into_parts().0;
        assert!(matches!(
            scheme.validator().validate(&parts).await,
            Err(ApiKeyAuthError::MissingKey)
        ));
    }
}
