//! JWT authentication scheme — the JWT specialization of [`CredentialScheme`].
//!
//! `JwtScheme` is a type alias over `CredentialScheme<U, JwtTokens<B>, …>`: it
//! *is* the credential scheme with the JWT [`TokenStrategy`](crate::authentication::token_strategy::TokenStrategy)
//! plugged in. The token-agnostic capability builders (`supports_2fa`,
//! `supports_oauth`, …) live on the generic scheme; only `new` and
//! `supports_elevation` — which name the JWT config — are defined here.

use tempered_core::{BannedTokenStore, TokenEpochStore, UserStore};

use crate::auth_validation::local_jwt_validator::JwtAuthConfig;
use crate::authentication::credential_scheme::{CredentialScheme, ElevatedCapabilities};
use crate::authentication::token_strategy::JwtTokens;

// Re-export the capability slots, wire types, and error at this module's original
// path (the facade and callers refer to `jwt_scheme::{TwoFa, Elevation, …}`).
pub use crate::authentication::credential_scheme::{
    CredentialError, Elevation, EmailVerify, OAuth, Passkeys, PasswordCredentials, PasswordReset,
    RegistrationData, TwoFa,
};
pub use crate::authentication::token_strategy::JwtToken;

/// JWT-based credential scheme: [`CredentialScheme`] with the JWT token strategy.
///
/// Generic slots (each defaults to `()` = disabled) match [`CredentialScheme`]:
/// `F` two-factor, `L` elevation, `R` password reset, `M` email verify,
/// `O` OAuth2, `K` passkeys.
pub type JwtScheme<U, B, F = (), L = (), R = (), M = (), O = (), K = ()> =
    CredentialScheme<U, JwtTokens<B>, F, L, R, M, O, K>;

impl<U, B> CredentialScheme<U, JwtTokens<B>, (), (), (), (), (), ()>
where
    U: UserStore,
    B: BannedTokenStore + Clone + Send + Sync + 'static,
{
    /// Create the JWT scheme: password login, logout, and JWT validation.
    ///
    /// The epoch store is required infrastructure, like the ban store: it is
    /// what lets a password change or account deletion revoke every
    /// outstanding token (validation rejects tokens issued before the user's
    /// recorded cutoff). Use `HashMapTokenEpochStore` in development and
    /// `RedisTokenEpochStore` (with a TTL ≥ the token TTL) in production.
    ///
    /// Opt into optional capabilities with the `supports_*` methods.
    pub fn new(
        user_store: U,
        jwt_config: JwtAuthConfig,
        banned_token_store: B,
        token_epoch_store: impl TokenEpochStore + 'static,
    ) -> Self {
        Self::from_tokens(
            user_store,
            JwtTokens::new(jwt_config, banned_token_store, token_epoch_store),
        )
    }
}

impl<U, B, F, R, M, O, K> CredentialScheme<U, JwtTokens<B>, F, (), R, M, O, K>
where
    B: BannedTokenStore + Clone + Send + Sync + 'static,
{
    /// Enable elevated ("sudo") JWTs from a separate config + banned-token store,
    /// lighting up [`SupportsElevation`](tempered_core::SupportsElevation) and
    /// [`HttpElevationScheme`](tempered_core::HttpElevationScheme).
    ///
    /// The elevated strategy shares the primary strategy's token-epoch store,
    /// so revoking all of a user's tokens (password change, account deletion)
    /// kills their elevated tokens too.
    // The return type spells out every capability slot on purpose: it is the
    // typestate transition. An alias would hide which slot changes.
    #[allow(clippy::type_complexity)]
    pub fn supports_elevation<Cfg>(
        self,
        elevated_banned_token_store: B,
        elevated_jwt_config: JwtAuthConfig,
        configure: Cfg,
    ) -> CredentialScheme<U, JwtTokens<B>, F, Elevation<JwtTokens<B>>, R, M, O, K>
    where
        Cfg: FnOnce(ElevatedCapabilities) -> ElevatedCapabilities,
    {
        let epoch = self.token_strategy().epoch();
        self.supports_elevation_with(
            JwtTokens::from_parts(elevated_jwt_config, elevated_banned_token_store, epoch),
            configure,
        )
    }
}

// ============================================================================
// Tests: OAuth capability issues a usable primary JWT
// ============================================================================

#[cfg(test)]
mod oauth_tests {
    use super::{JwtScheme, OAuth};
    use crate::auth_validation::local_jwt_validator::JwtAuthConfig;
    use crate::oauth::OAuthFlow;
    use crate::persistence::{
        HashMapTokenEpochStore, HashMapUserStore, HashSetBannedTokenStore,
        hashmap_oauth_identity_store::HashMapOAuthIdentityStore,
        hashmap_oauth_state_store::HashMapOAuthStateStore,
    };
    use async_trait::async_trait;
    use secrecy::Secret;
    use tempered_core::{
        AuthValidator, AuthenticationScheme, OAuthHttpClient, OAuthHttpError, OAuthProviderConfig,
        OAuthUserInfo, SupportsOAuth2,
    };

    #[derive(Clone)]
    struct MockClient {
        email: String,
    }

    #[async_trait]
    impl OAuthHttpClient for MockClient {
        async fn exchange_code(
            &self,
            _config: &OAuthProviderConfig,
            _code: &str,
            _code_verifier: &str,
        ) -> Result<String, OAuthHttpError> {
            Ok("access-token".to_string())
        }

        async fn fetch_user_info(
            &self,
            _config: &OAuthProviderConfig,
            _access_token: &str,
        ) -> Result<OAuthUserInfo, OAuthHttpError> {
            Ok(OAuthUserInfo {
                subject: "sub-123".to_string(),
                email: self.email.clone(),
                email_verified: true,
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

    fn jwt_config() -> JwtAuthConfig {
        JwtAuthConfig {
            jwt_cookie_name: "jwt".to_string(),
            jwt_secret: Secret::new("a-test-secret-that-is-long-enough".to_string()),
            token_ttl_in_seconds: 3600,
            audience: None,
            issuer: None,
        }
    }

    type TestScheme = JwtScheme<
        HashMapUserStore,
        HashSetBannedTokenStore,
        (),
        (),
        (),
        (),
        OAuth<HashMapOAuthStateStore, HashMapOAuthIdentityStore, MockClient>,
    >;

    fn scheme_with_oauth() -> TestScheme {
        let flow = OAuthFlow::new(
            HashMapOAuthStateStore::new(),
            HashMapOAuthIdentityStore::new(),
            MockClient {
                email: "user@example.com".to_string(),
            },
        )
        .with_provider(provider());

        JwtScheme::new(
            HashMapUserStore::new(),
            jwt_config(),
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .supports_oauth(flow)
    }

    #[tokio::test]
    async fn completing_oauth_issues_a_jwt_that_validates() {
        let scheme = scheme_with_oauth();

        let auth = scheme.begin_oauth("google").await.unwrap();
        assert!(auth.authorize_url.contains("client_id=cid"));

        let token = scheme
            .complete_oauth("google", "auth-code", &auth.state, &auth.state)
            .await
            .unwrap();

        let parts = http::Request::builder()
            .header("cookie", format!("jwt={}", token.as_str()))
            .body(())
            .unwrap()
            .into_parts()
            .0;
        assert!(scheme.validator().validate(&parts).await.is_ok());
    }

    #[tokio::test]
    async fn mismatched_cookie_state_is_rejected() {
        let scheme = scheme_with_oauth();
        let auth = scheme.begin_oauth("google").await.unwrap();

        let result = scheme
            .complete_oauth("google", "code", &auth.state, "attacker-cookie")
            .await;
        assert!(result.is_err());
    }
}

// ============================================================================
// Tests: Passkey capability issues a usable primary JWT
// ============================================================================

#[cfg(test)]
mod passkey_tests {
    use super::{JwtScheme, Passkeys};
    use crate::auth_validation::local_jwt_validator::JwtAuthConfig;
    use crate::authentication::credential_scheme::CredentialError;
    use crate::passkey::PasskeyFlow;
    use crate::passkey::flow::test_support::{MockVerifier, reply_with_count};
    use crate::persistence::{
        HashMapTokenEpochStore, HashMapUserStore, HashSetBannedTokenStore,
        hashmap_challenge_store::HashMapChallengeStore,
        hashmap_passkey_credential_store::HashMapPasskeyCredentialStore,
    };
    use secrecy::Secret;
    use tempered_core::{
        AuthValidator, AuthenticationScheme, Email, Password, SupportsPasskeys, User, UserStore,
        UserStoreError,
    };

    type TestScheme = JwtScheme<
        HashMapUserStore,
        HashSetBannedTokenStore,
        (),
        (),
        (),
        (),
        (),
        Passkeys<HashMapPasskeyCredentialStore, HashMapChallengeStore, MockVerifier>,
    >;

    /// A passkey scheme whose user store already holds [`email`]'s account
    /// (passkeys are enrolled for, and log in to, existing accounts). The store
    /// handle is returned so a test can remove the account.
    async fn scheme_with_passkeys() -> (TestScheme, HashMapUserStore) {
        let user_store = HashMapUserStore::new();
        let password = Password::try_from(Secret::new("a-long-password".to_string())).unwrap();
        user_store
            .add_user(User::new(email(), password, false))
            .await
            .unwrap();

        let flow = PasskeyFlow::new(
            HashMapPasskeyCredentialStore::new(),
            HashMapChallengeStore::new(),
            MockVerifier,
        );

        let scheme = JwtScheme::new(
            user_store.clone(),
            jwt_config(),
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .supports_passkeys(flow);
        (scheme, user_store)
    }

    fn jwt_config() -> JwtAuthConfig {
        JwtAuthConfig {
            jwt_cookie_name: "jwt".to_string(),
            jwt_secret: Secret::new("a-test-secret-that-is-long-enough".to_string()),
            token_ttl_in_seconds: 3600,
            audience: None,
            issuer: None,
        }
    }

    fn email() -> Email {
        Email::try_from(Secret::new("user@example.com".to_string())).unwrap()
    }

    async fn enroll(scheme: &TestScheme, cred_id: &str) {
        let ceremony = scheme.start_passkey_registration(email()).await.unwrap();
        let response = reply_with_count(&ceremony, cred_id, 0);
        scheme
            .finish_passkey_registration(email(), ceremony.ceremony_id, response)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn register_then_authenticate_issues_a_jwt_that_validates() {
        let (scheme, _users) = scheme_with_passkeys().await;

        enroll(&scheme, "cred-abc").await;

        let ceremony = scheme
            .start_passkey_authentication(Some(email()))
            .await
            .unwrap();
        let token = scheme
            .finish_passkey_authentication(
                ceremony.ceremony_id.clone(),
                reply_with_count(&ceremony, "cred-abc", 1),
            )
            .await
            .unwrap();

        let parts = http::Request::builder()
            .header("cookie", format!("jwt={}", token.as_str()))
            .body(())
            .unwrap()
            .into_parts()
            .0;
        assert!(scheme.validator().validate(&parts).await.is_ok());
    }

    #[tokio::test]
    async fn passkey_of_a_deleted_account_cannot_log_in() {
        let (scheme, users) = scheme_with_passkeys().await;

        enroll(&scheme, "cred-abc").await;

        // The account is removed, but the credential is still in the passkey store.
        users.delete_user(&email()).await.unwrap();

        let ceremony = scheme
            .start_passkey_authentication(Some(email()))
            .await
            .unwrap();
        let result = scheme
            .finish_passkey_authentication(
                ceremony.ceremony_id.clone(),
                reply_with_count(&ceremony, "cred-abc", 1),
            )
            .await;
        assert!(matches!(
            result,
            Err(CredentialError::UserStoreError(
                UserStoreError::UserNotFound
            ))
        ));
    }

    #[tokio::test]
    async fn cloned_authenticator_is_rejected() {
        let (scheme, _users) = scheme_with_passkeys().await;

        enroll(&scheme, "cred-abc").await;

        let ceremony = scheme
            .start_passkey_authentication(Some(email()))
            .await
            .unwrap();
        scheme
            .finish_passkey_authentication(
                ceremony.ceremony_id.clone(),
                reply_with_count(&ceremony, "cred-abc", 5),
            )
            .await
            .unwrap();

        let ceremony = scheme
            .start_passkey_authentication(Some(email()))
            .await
            .unwrap();
        let result = scheme
            .finish_passkey_authentication(
                ceremony.ceremony_id.clone(),
                reply_with_count(&ceremony, "cred-abc", 3),
            )
            .await;
        assert!(result.is_err());
    }
}
