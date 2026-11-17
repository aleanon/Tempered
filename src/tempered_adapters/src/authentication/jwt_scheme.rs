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
    use crate::authentication::credential_scheme::CredentialError;
    use crate::authentication::token_strategy::JwtToken;
    use crate::email::MockEmailClient;
    use crate::http::HttpResponseBuilder;
    use crate::oauth::OAuthFlow;
    use crate::persistence::{
        HashMapTokenEpochStore, HashMapTwoFaCodeStore, HashMapUserStore, HashSetBannedTokenStore,
        hashmap_oauth_identity_store::HashMapOAuthIdentityStore,
        hashmap_oauth_state_store::HashMapOAuthStateStore,
    };
    use async_trait::async_trait;
    use secrecy::{ExposeSecret, Secret};
    use tempered_core::{
        AuthValidator, AuthenticationScheme, Email, HttpOAuth2Scheme, LoginOutcome,
        OAuthHttpClient, OAuthHttpError, OAuthProviderConfig, OAuthUserInfo, Password,
        SupportsOAuth2, SupportsTwoFactor, TwoFaCodeStore, User, UserStore,
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

    fn email() -> Email {
        Email::try_from(Secret::new("user@example.com".to_string())).unwrap()
    }

    /// The provider vouches for `user@example.com`.
    fn flow() -> OAuthFlow<HashMapOAuthStateStore, HashMapOAuthIdentityStore, MockClient> {
        OAuthFlow::new(
            HashMapOAuthStateStore::new(),
            HashMapOAuthIdentityStore::new(),
            MockClient {
                email: "user@example.com".to_string(),
            },
        )
        .with_provider(provider())
    }

    /// A scheme with OAuth and no 2FA, plus a handle on its user store.
    fn scheme_with_oauth() -> (TestScheme, HashMapUserStore) {
        let users = HashMapUserStore::new();
        let scheme = JwtScheme::new(
            users.clone(),
            jwt_config(),
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .supports_oauth(flow());
        (scheme, users)
    }

    async fn add_account(users: &HashMapUserStore, password: &str, requires_2fa: bool) {
        let password = Password::try_from(Secret::new(password.to_string())).unwrap();
        users
            .add_user(User::new(email(), password, requires_2fa))
            .await
            .unwrap();
    }

    /// Run both OAuth legs as the same browser.
    async fn oauth_login<S: SupportsOAuth2>(
        scheme: &S,
    ) -> Result<LoginOutcome<S::Token>, S::OAuth2Error> {
        let auth = scheme.begin_oauth("google").await.unwrap();
        scheme
            .complete_oauth("google", "auth-code", &auth.state, &auth.state)
            .await
    }

    async fn validates<S>(scheme: &S, token: &JwtToken) -> bool
    where
        S: AuthenticationScheme,
        S::Validator: AuthValidator<RequestParts = http::request::Parts>,
    {
        let parts = http::Request::builder()
            .header("cookie", format!("jwt={}", token.as_str()))
            .body(())
            .unwrap()
            .into_parts()
            .0;
        scheme.validator().validate(&parts).await.is_ok()
    }

    #[tokio::test]
    async fn first_oauth_login_creates_the_account_and_logs_in() {
        let (scheme, users) = scheme_with_oauth();
        assert!(users.get_user(&email()).await.is_err());

        let auth = scheme.begin_oauth("google").await.unwrap();
        assert!(auth.authorize_url.contains("client_id=cid"));
        let outcome = scheme
            .complete_oauth("google", "auth-code", &auth.state, &auth.state)
            .await
            .unwrap();

        let LoginOutcome::Success(token) = outcome else {
            panic!("expected an immediate login");
        };
        assert!(validates(&scheme, &token).await);

        // The account now exists, without 2FA, and with a password nobody knows.
        let user = users.get_user(&email()).await.unwrap();
        assert!(!user.requires_2fa);
        for guess in ["", "password", "user@example.com"] {
            if let Ok(guess) = Password::try_from(Secret::new(guess.to_string())) {
                assert!(users.authenticate_user(&email(), &guess).await.is_err());
            }
        }
    }

    #[tokio::test]
    async fn each_provider_created_account_gets_its_own_password() {
        let (first, first_users) = scheme_with_oauth();
        let (second, second_users) = scheme_with_oauth();
        oauth_login(&first).await.unwrap();
        oauth_login(&second).await.unwrap();

        let a = first_users.get_user(&email()).await.unwrap().password;
        let b = second_users.get_user(&email()).await.unwrap().password;
        assert!(a != b);
        assert_eq!(a.as_ref().expose_secret().len(), 43);
    }

    #[tokio::test]
    async fn oauth_login_to_an_existing_account_leaves_it_untouched() {
        let (scheme, users) = scheme_with_oauth();
        add_account(&users, "the-users-own-password", false).await;

        let outcome = oauth_login(&scheme).await.unwrap();
        let LoginOutcome::Success(token) = outcome else {
            panic!("expected an immediate login");
        };
        assert!(validates(&scheme, &token).await);

        // Same account: its password still works, and it is the only account.
        let password = Password::try_from(Secret::new("the-users-own-password".into())).unwrap();
        assert!(users.authenticate_user(&email(), &password).await.is_ok());

        // A second OAuth login is just another login.
        assert!(matches!(
            oauth_login(&scheme).await.unwrap(),
            LoginOutcome::Success(_)
        ));
    }

    #[tokio::test]
    async fn oauth_login_does_not_skip_two_factor() {
        let users = HashMapUserStore::new();
        add_account(&users, "the-users-own-password", true).await;
        let codes = HashMapTwoFaCodeStore::new();
        let scheme = JwtScheme::new(
            users.clone(),
            jwt_config(),
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .supports_2fa(codes.clone(), MockEmailClient::new())
        .supports_oauth(flow());

        // The provider login yields a pending challenge, not a token.
        let outcome = oauth_login(&scheme).await.unwrap();
        let LoginOutcome::Requires2Fa {
            email: challenged,
            attempt_id,
        } = outcome
        else {
            panic!("a 2FA account must not be logged in by the provider alone");
        };
        assert_eq!(challenged, email());

        // The challenge is a real one: a wrong code fails, the issued code
        // completes the login.
        let (stored_attempt, code) = codes
            .get_login_attempt_id_and_two_fa_code(&email())
            .await
            .unwrap();
        assert_eq!(stored_attempt, attempt_id);

        let token = scheme.verify_2fa(email(), attempt_id, code).await.unwrap();
        assert!(validates(&scheme, &token).await);
    }

    #[tokio::test]
    async fn oauth_login_to_a_two_factor_account_fails_closed_without_two_factor_support() {
        // The scheme has no 2FA capability, so it cannot challenge this account.
        let (scheme, users) = scheme_with_oauth();
        add_account(&users, "the-users-own-password", true).await;

        let result = oauth_login(&scheme).await;
        assert!(matches!(result, Err(CredentialError::TwoFaNotConfigured)));
    }

    fn header<'a>(response: &'a http::Response<String>, name: &str) -> Vec<&'a str> {
        response
            .headers()
            .get_all(name)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect()
    }

    #[tokio::test]
    async fn successful_callback_sets_the_auth_cookie_and_enters_the_app() {
        let (scheme, _users) = scheme_with_oauth();
        let scheme = scheme.oauth_post_login_redirect("/app");
        let outcome = oauth_login(&scheme).await.unwrap();

        let response = scheme
            .create_oauth_callback_response(HttpResponseBuilder::new(), outcome)
            .unwrap();

        assert_eq!(response.status(), 302);
        assert_eq!(header(&response, "location"), ["/app"]);
        let cookies = header(&response, "set-cookie");
        assert!(cookies.iter().any(|c| c.starts_with("jwt=ey")));
        assert!(cookies.iter().any(|c| c.starts_with("oauth_state=;")));
    }

    #[tokio::test]
    async fn two_factor_callback_issues_no_cookie_and_redirects_to_the_code_step() {
        let users = HashMapUserStore::new();
        add_account(&users, "the-users-own-password", true).await;
        let scheme = JwtScheme::new(
            users,
            jwt_config(),
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .supports_2fa(HashMapTwoFaCodeStore::new(), MockEmailClient::new())
        .supports_oauth(flow())
        .oauth_two_fa_redirect("/login?step=2fa#code");

        let outcome = oauth_login(&scheme).await.unwrap();
        let LoginOutcome::Requires2Fa { attempt_id, .. } = &outcome else {
            panic!("expected a 2FA challenge");
        };
        let attempt_id = attempt_id.to_string();

        let response = scheme
            .create_oauth_callback_response(HttpResponseBuilder::new(), outcome)
            .unwrap();

        assert_eq!(response.status(), 302);

        // No session cookie: only the cleared state cookie and the hand-off.
        let cookies = header(&response, "set-cookie");
        assert_eq!(cookies.len(), 2);
        assert!(cookies.iter().any(|c| c.starts_with("oauth_state=;")));
        assert!(!cookies.iter().any(|c| c.starts_with("jwt=")));

        // The URL carries only a marker: no email, no attempt id.
        let location = header(&response, "location")[0];
        assert_eq!(location, "/login?step=2fa&oauth_2fa=required#code");

        // The hand-off cookie is short-lived, script-readable, and holds what
        // the page needs to call the 2FA verification route.
        let handoff = cookies
            .iter()
            .find(|c| c.starts_with("oauth_2fa="))
            .expect("hand-off cookie");
        let (value, attributes) = handoff["oauth_2fa=".len()..].split_once("; ").unwrap();
        assert!(attributes.contains("Max-Age=600"));
        assert!(attributes.contains("Secure"));
        assert!(attributes.contains("SameSite=Lax"));
        assert!(!attributes.contains("HttpOnly"));
        let params: std::collections::HashMap<_, _> = url::form_urlencoded::parse(value.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(params["loginAttemptId"], attempt_id);
        assert_eq!(params["email"], "user@example.com");
    }

    #[tokio::test]
    async fn mismatched_cookie_state_is_rejected() {
        let (scheme, users) = scheme_with_oauth();
        let auth = scheme.begin_oauth("google").await.unwrap();

        let result = scheme
            .complete_oauth("google", "code", &auth.state, "attacker-cookie")
            .await;
        assert!(result.is_err());
        // A rejected callback creates nothing.
        assert!(users.get_user(&email()).await.is_err());
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
    use crate::passkey::flow::test_support::{MockVerifier, reply_with_count};
    use crate::passkey::{PasskeyFlow, PasskeyFlowError};
    use crate::persistence::{
        HashMapTokenEpochStore, HashMapUserStore, HashSetBannedTokenStore,
        hashmap_challenge_store::HashMapChallengeStore,
        hashmap_passkey_credential_store::HashMapPasskeyCredentialStore,
    };
    use secrecy::Secret;
    use tempered_core::{
        AuthValidator, AuthenticationScheme, CredentialId, Email, PasskeyCredential,
        PasskeyCredentialStore, PasskeyStoreError, Password, SupportsAccountDeletion,
        SupportsPasskeys, User, UserStore, UserStoreError,
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
    async fn deleting_the_account_removes_its_passkeys() {
        let (scheme, users) = scheme_with_passkeys().await;
        enroll(&scheme, "cred-abc").await;

        scheme.delete_account(email()).await.unwrap();

        // Someone later registers the same address: a brand-new account.
        let password = Password::try_from(Secret::new("another-password".to_string())).unwrap();
        users
            .add_user(User::new(email(), password, false))
            .await
            .unwrap();

        // The previous owner's passkey must not log in to it.
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
            Err(CredentialError::Passkey(PasskeyFlowError::Credential(
                PasskeyStoreError::CredentialNotFound
            )))
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

    /// A credential store that is down: every call fails.
    #[derive(Clone)]
    struct UnavailableCredentialStore;

    #[async_trait::async_trait]
    impl PasskeyCredentialStore for UnavailableCredentialStore {
        async fn add_credential(&self, _: PasskeyCredential) -> Result<(), PasskeyStoreError> {
            Err(PasskeyStoreError::UnexpectedError("down".into()))
        }
        async fn get_credential(
            &self,
            _: &CredentialId,
        ) -> Result<PasskeyCredential, PasskeyStoreError> {
            Err(PasskeyStoreError::UnexpectedError("down".into()))
        }
        async fn list_for_user(
            &self,
            _: &Email,
        ) -> Result<Vec<PasskeyCredential>, PasskeyStoreError> {
            Err(PasskeyStoreError::UnexpectedError("down".into()))
        }
        async fn update_after_authentication(
            &self,
            _: &CredentialId,
            _: u32,
            _: Option<Vec<u8>>,
        ) -> Result<(), PasskeyStoreError> {
            Err(PasskeyStoreError::UnexpectedError("down".into()))
        }
        async fn delete_all_for_user(&self, _: &Email) -> Result<(), PasskeyStoreError> {
            Err(PasskeyStoreError::UnexpectedError("down".into()))
        }
    }

    #[tokio::test]
    async fn account_is_not_deleted_if_its_passkeys_cannot_be_removed() {
        let users = HashMapUserStore::new();
        let password = Password::try_from(Secret::new("a-long-password".to_string())).unwrap();
        users
            .add_user(User::new(email(), password, false))
            .await
            .unwrap();
        let scheme = JwtScheme::new(
            users.clone(),
            jwt_config(),
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .supports_passkeys(PasskeyFlow::new(
            UnavailableCredentialStore,
            HashMapChallengeStore::new(),
            MockVerifier,
        ));

        // Deletion fails as a whole, leaving the account in place to retry —
        // not a deleted account whose passkeys are still in the store.
        assert!(scheme.delete_account(email()).await.is_err());
        assert!(users.get_user(&email()).await.is_ok());
    }
}
