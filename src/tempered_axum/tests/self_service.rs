//! The self-service routes mount next to the login ones (no path clashes)
//! and need a login. In-memory stores and `tower::oneshot`.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use secrecy::Secret;
use tempered_adapters::auth_validation::local_jwt_validator::JwtAuthConfig;
use tempered_adapters::authentication::jwt_scheme::JwtScheme;
use tempered_adapters::oauth::OAuthFlow;
use tempered_adapters::passkey::PasskeyFlow;
use tempered_adapters::persistence::{
    HashMapChallengeStore, HashMapOAuthIdentityStore, HashMapOAuthStateStore,
    HashMapPasskeyCredentialStore, HashMapTokenEpochStore, HashMapUserStore,
    HashSetBannedTokenStore,
};
use tempered_axum::auth_service::auth_service;
use tempered_core::{
    CeremonyStart, CeremonyState, Email, OAuthHttpClient, OAuthHttpError, OAuthProviderConfig,
    OAuthUserInfo, PasskeyCredential, TokenResponse, VerifiedAssertion, VerifiedRegistration,
    WebAuthnError, WebAuthnVerifier,
};

/// Never called: these requests stop at the login check.
#[derive(Clone)]
struct NoVerifier;

impl WebAuthnVerifier for NoVerifier {
    fn start_registration(
        &self,
        _: &Email,
        _: &[PasskeyCredential],
    ) -> Result<CeremonyStart, WebAuthnError> {
        unreachable!()
    }
    fn finish_registration(
        &self,
        _: &CeremonyState,
        _: &serde_json::Value,
    ) -> Result<VerifiedRegistration, WebAuthnError> {
        unreachable!()
    }
    fn start_authentication(
        &self,
        _: &[PasskeyCredential],
    ) -> Result<CeremonyStart, WebAuthnError> {
        unreachable!()
    }
    fn finish_authentication(
        &self,
        _: &CeremonyState,
        _: &serde_json::Value,
        _: &PasskeyCredential,
    ) -> Result<VerifiedAssertion, WebAuthnError> {
        unreachable!()
    }
}
use tower::ServiceExt;

#[derive(Clone)]
struct NoProvider;

#[async_trait::async_trait]
impl OAuthHttpClient for NoProvider {
    async fn exchange_code(
        &self,
        _: &OAuthProviderConfig,
        _: &str,
        _: &str,
    ) -> Result<TokenResponse, OAuthHttpError> {
        unreachable!()
    }
    async fn fetch_user_info(
        &self,
        _: &OAuthProviderConfig,
        _: &str,
    ) -> Result<OAuthUserInfo, OAuthHttpError> {
        unreachable!()
    }
    async fn fetch_json(&self, _: &str) -> Result<serde_json::Value, OAuthHttpError> {
        unreachable!()
    }
}

#[tokio::test]
async fn the_self_service_routes_mount_and_need_a_login() {
    let scheme = JwtScheme::new(
        HashMapUserStore::new(),
        JwtAuthConfig {
            jwt_cookie_name: "jwt".to_string(),
            jwt_secret: Secret::new("a-test-secret-that-is-long-enough".to_string()),
            token_ttl_in_seconds: 300,
            audience: None,
            issuer: None,
        },
        HashSetBannedTokenStore::new(),
        HashMapTokenEpochStore::new(),
    )
    .supports_oauth(OAuthFlow::new(
        HashMapOAuthStateStore::new(),
        HashMapOAuthIdentityStore::new(),
        NoProvider,
    ))
    .supports_passkeys(PasskeyFlow::new(
        HashMapPasskeyCredentialStore::new(),
        HashMapChallengeStore::new(),
        NoVerifier,
    ));
    let app: Router = auth_service(scheme, String::new()).into();
    for (method, path) in [
        ("GET", "/oauth/links"),
        ("POST", "/oauth/google/link"),
        ("DELETE", "/oauth/links/google"),
        ("GET", "/passkey/credentials"),
        ("PATCH", "/passkey/credentials/abc"),
        ("DELETE", "/passkey/credentials/abc"),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap();
        let status = app.clone().oneshot(request).await.unwrap().status();
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}");
    }

    // Another site cannot start a link in a visitor's browser.
    let cross = Request::post("/oauth/google/link")
        .header("sec-fetch-site", "cross-site")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(cross).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
}
