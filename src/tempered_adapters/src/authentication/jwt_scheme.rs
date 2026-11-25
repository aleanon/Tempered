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
use crate::authentication::token_strategy::{JwtTokens, RefreshTokens};

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
    ///
    /// # Panics
    ///
    /// If the elevated config signs with the primary config's secret. A
    /// login token would then verify as an elevated one wherever the two
    /// configs also agree on audience and issuer, and the sudo step would
    /// protect nothing. Give elevation its own secret.
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
        assert!(
            !self
                .token_strategy()
                .shares_secret_with(&elevated_jwt_config),
            "the elevated JWT config uses the primary JWT secret; give elevation its own secret",
        );
        let epoch = self.token_strategy().epoch();
        self.supports_elevation_with(
            JwtTokens::from_parts(elevated_jwt_config, elevated_banned_token_store, epoch),
            configure,
        )
    }
}

impl<U, B, F, L, R, M, O, K> CredentialScheme<U, JwtTokens<B>, F, L, R, M, O, K>
where
    B: BannedTokenStore + Clone,
{
    /// Issue a refresh token with every login, and serve `POST /refresh`,
    /// which trades one for a new JWT and refresh token. Keep the JWT short
    /// (`token_ttl_in_seconds` of minutes) when you use this: the refresh
    /// token carries the long session, and can be revoked. See
    /// [`RefreshTokens`] for rotation and reuse detection.
    pub fn supports_refresh_tokens(self, refresh: RefreshTokens) -> Self {
        self.map_tokens(|tokens| tokens.with_refresh(refresh))
    }

    /// Also return the tokens in login response bodies (`accessToken`,
    /// `refreshToken`, `expiresIn`), for clients that send
    /// `Authorization: Bearer` instead of cookies: mobile apps, or a front
    /// end on another origin. The cookies are still set. Only for apps that
    /// need it: a token a script can read is a token an XSS can steal.
    pub fn tokens_in_body(self) -> Self {
        self.map_tokens(JwtTokens::with_tokens_in_body)
    }

    /// Add the app's own claims (roles, tenant, ...) to every JWT, under
    /// `ext` (see [`ClaimsProvider`](crate::authentication::token_strategy::ClaimsProvider)).
    pub fn jwt_claims(
        self,
        provider: impl crate::authentication::token_strategy::ClaimsProvider + 'static,
    ) -> Self {
        self.map_tokens(|tokens| tokens.with_claims(provider))
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
    use crate::passkey::PasskeyFlow;
    use crate::passkey::flow::test_support::{MockVerifier, reply_with_count};
    use crate::persistence::{
        HashMapChallengeStore, HashMapEmailVerificationTokenStore, HashMapPasskeyCredentialStore,
        HashMapTokenEpochStore, HashMapTwoFaCodeStore, HashMapUserStore, HashSetBannedTokenStore,
        hashmap_oauth_identity_store::HashMapOAuthIdentityStore,
        hashmap_oauth_state_store::HashMapOAuthStateStore,
    };
    use async_trait::async_trait;
    use secrecy::{ExposeSecret, Secret};
    use tempered_core::{
        AuthValidator, AuthenticationScheme, Email, EmailVerificationTokenStore, HttpOAuth2Scheme,
        LoginOutcome, OAuthHttpClient, OAuthHttpError, OAuthIdentityStore, OAuthProviderConfig,
        OAuthUserInfo, PasskeyCredentialStore, Password, SupportsAccountDeletion, SupportsOAuth2,
        SupportsPasskeys, SupportsTwoFactor, TokenEpochStore, TwoFaCodeStore, User, UserStore,
    };

    #[derive(Clone)]
    struct MockClient {
        email: String,
    }

    #[async_trait]
    impl OAuthHttpClient for MockClient {
        async fn fetch_json(&self, _: &str) -> Result<serde_json::Value, OAuthHttpError> {
            unreachable!("no OIDC in these tests")
        }

        async fn exchange_code(
            &self,
            _config: &OAuthProviderConfig,
            _code: &str,
            _code_verifier: &str,
        ) -> Result<tempered_core::TokenResponse, OAuthHttpError> {
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
            oidc: None,
            emails_url: None,
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

    /// Like [`flow`], for an account whose address is already proven: another
    /// provider is linked to it, so a first login through this one leaves the
    /// account (and its 2FA requirement) as it is.
    async fn flow_for_a_proven_account()
    -> OAuthFlow<HashMapOAuthStateStore, HashMapOAuthIdentityStore, MockClient> {
        let identities = HashMapOAuthIdentityStore::new();
        identities
            .link_identity("github".to_string(), "gh-1".to_string(), email())
            .await
            .unwrap();
        OAuthFlow::new(
            HashMapOAuthStateStore::new(),
            identities,
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

    /// The parts of an account that let someone in, as handles a test can
    /// inspect after an OAuth login.
    struct Account {
        users: HashMapUserStore,
        epochs: HashMapTokenEpochStore,
        passkeys: HashMapPasskeyCredentialStore,
        identities: HashMapOAuthIdentityStore,
        verified: HashMapEmailVerificationTokenStore,
    }

    impl Account {
        /// An account for [`email`] created by signup, with a password and a
        /// passkey, and (as a stand-in for a live session) no revocation yet.
        async fn signed_up() -> Self {
            let account = Self {
                users: HashMapUserStore::new(),
                epochs: HashMapTokenEpochStore::new(),
                passkeys: HashMapPasskeyCredentialStore::new(),
                identities: HashMapOAuthIdentityStore::new(),
                verified: HashMapEmailVerificationTokenStore::new(),
            };
            add_account(&account.users, SIGNUP_PASSWORD, false).await;
            account
        }

        /// A scheme over this account's stores with OAuth, passkeys and email
        /// verification, with one passkey already enrolled.
        async fn scheme(
            &self,
        ) -> impl SupportsOAuth2<Token = JwtToken> + SupportsAccountDeletion + use<> {
            let scheme = JwtScheme::new(
                self.users.clone(),
                jwt_config(),
                HashSetBannedTokenStore::new(),
                self.epochs.clone(),
            )
            .supports_email_verification(self.verified.clone(), MockEmailClient::new())
            .supports_oauth(
                OAuthFlow::new(
                    HashMapOAuthStateStore::new(),
                    self.identities.clone(),
                    MockClient {
                        email: "user@example.com".to_string(),
                    },
                )
                .with_provider(provider()),
            )
            .supports_passkeys(PasskeyFlow::new(
                self.passkeys.clone(),
                HashMapChallengeStore::new(),
                MockVerifier,
            ));

            let ceremony = scheme.start_passkey_registration(email()).await.unwrap();
            let response = reply_with_count(&ceremony, "cred-from-signup", 0);
            scheme
                .finish_passkey_registration(email(), ceremony.ceremony_id, response)
                .await
                .unwrap();
            scheme
        }

        async fn password_works(&self, password: &str) -> bool {
            let password = Password::try_from(Secret::new(password.to_string())).unwrap();
            self.users
                .authenticate_user(&email(), &password)
                .await
                .is_ok()
        }

        async fn passkey_count(&self) -> usize {
            self.passkeys.list_for_user(&email()).await.unwrap().len()
        }

        async fn sessions_revoked(&self) -> bool {
            self.epochs.min_valid_iat(&email()).await.unwrap().is_some()
        }

        async fn assert_untouched(&self) {
            assert!(self.password_works(SIGNUP_PASSWORD).await);
            assert_eq!(self.passkey_count().await, 1);
            assert!(!self.sessions_revoked().await);
        }
    }

    const SIGNUP_PASSWORD: &str = "chosen-by-whoever-signed-up";

    #[tokio::test]
    async fn first_oauth_login_to_an_unproven_account_removes_every_earlier_way_in() {
        // Signup never proved the address. Whoever signed up (possibly an
        // attacker squatting on the victim's address) holds a password, a
        // passkey and maybe a session.
        let account = Account::signed_up().await;
        let scheme = account.scheme().await;
        account.assert_untouched().await;

        let outcome = oauth_login(&scheme).await.unwrap();
        assert!(matches!(outcome, LoginOutcome::Success(_)));

        assert!(!account.password_works(SIGNUP_PASSWORD).await);
        assert_eq!(account.passkey_count().await, 0);
        assert!(account.sessions_revoked().await);
    }

    #[tokio::test]
    async fn later_oauth_logins_leave_the_account_untouched() {
        let account = Account::signed_up().await;
        let scheme = account.scheme().await;
        oauth_login(&scheme).await.unwrap();

        // The owner sets a password of their own (as password reset would).
        let own = Password::try_from(Secret::new("the-owners-new-password".into())).unwrap();
        account.users.set_new_password(&email(), own).await.unwrap();

        // The identity is linked now: this is just another login.
        let outcome = oauth_login(&scheme).await.unwrap();
        assert!(matches!(outcome, LoginOutcome::Success(_)));
        assert!(account.password_works("the-owners-new-password").await);
    }

    #[tokio::test]
    async fn a_provider_login_marks_the_address_verified() {
        let account = Account::signed_up().await;
        let scheme = account.scheme().await;
        assert!(!account.verified.is_verified(&email()).await.unwrap());

        // The provider vouches for the address, so the account is proven
        // from now on (and a later first link to another provider leaves it
        // alone).
        oauth_login(&scheme).await.unwrap();
        assert!(account.verified.is_verified(&email()).await.unwrap());
    }

    #[tokio::test]
    async fn first_oauth_login_to_a_verified_account_leaves_it_untouched() {
        // The owner proved the address through email verification, so the
        // password, passkey and sessions are theirs.
        let account = Account::signed_up().await;
        account.verified.mark_verified(&email()).await.unwrap();
        let scheme = account.scheme().await;

        let outcome = oauth_login(&scheme).await.unwrap();
        assert!(matches!(outcome, LoginOutcome::Success(_)));
        account.assert_untouched().await;
    }

    #[tokio::test]
    async fn a_verified_mark_does_not_outlive_its_account() {
        // The owner verified the address, then deleted the account.
        let account = Account::signed_up().await;
        account.verified.mark_verified(&email()).await.unwrap();
        let scheme = account.scheme().await;
        assert!(scheme.delete_account(email()).await.is_ok());
        assert!(!account.verified.is_verified(&email()).await.unwrap());

        // Someone signs up with the same address again. Nothing proves this
        // new account's address, so a provider login secures it.
        add_account(&account.users, SIGNUP_PASSWORD, false).await;
        let outcome = oauth_login(&scheme).await.unwrap();
        assert!(matches!(outcome, LoginOutcome::Success(_)));
        assert!(!account.password_works(SIGNUP_PASSWORD).await);
    }

    #[tokio::test]
    async fn provider_links_do_not_outlive_their_account() {
        // The owner logged in through the provider (linking it), then deleted
        // the account.
        let account = Account::signed_up().await;
        account.verified.mark_verified(&email()).await.unwrap();
        let scheme = account.scheme().await;
        oauth_login(&scheme).await.unwrap();
        assert!(
            account
                .identities
                .has_identity_for_email(&email())
                .await
                .unwrap()
        );

        assert!(scheme.delete_account(email()).await.is_ok());
        assert!(
            !account
                .identities
                .has_identity_for_email(&email())
                .await
                .unwrap()
        );

        // Someone signs up with the same address again. The old link neither
        // logs the provider's user straight in nor counts as proof: the new
        // account is secured like any other unproven one.
        add_account(&account.users, SIGNUP_PASSWORD, false).await;
        let outcome = oauth_login(&scheme).await.unwrap();
        assert!(matches!(outcome, LoginOutcome::Success(_)));
        assert!(!account.password_works(SIGNUP_PASSWORD).await);
    }

    #[tokio::test]
    async fn first_login_through_a_second_provider_leaves_the_account_untouched() {
        // Another provider already proved the address for this account.
        let account = Account::signed_up().await;
        account
            .identities
            .link_identity("github".to_string(), "gh-1".to_string(), email())
            .await
            .unwrap();
        let scheme = account.scheme().await;

        let outcome = oauth_login(&scheme).await.unwrap();
        assert!(matches!(outcome, LoginOutcome::Success(_)));
        account.assert_untouched().await;
    }

    #[tokio::test]
    async fn without_email_verification_an_existing_account_counts_as_unproven() {
        // No verification capability on the scheme: nothing has proven the
        // address, so the signup password does not survive.
        let (scheme, users) = scheme_with_oauth();
        add_account(&users, SIGNUP_PASSWORD, false).await;

        let outcome = oauth_login(&scheme).await.unwrap();
        let LoginOutcome::Success(token) = outcome else {
            panic!("expected an immediate login");
        };
        // The session issued by this login is not caught by the revocation.
        assert!(validates(&scheme, &token).await);

        let password = Password::try_from(Secret::new(SIGNUP_PASSWORD.into())).unwrap();
        assert!(users.authenticate_user(&email(), &password).await.is_err());
    }

    /// The user changed their address at the provider after linking. The
    /// identity still logs in to its account (no lockout, nothing secured
    /// or moved), but the provider no longer vouches for the old address, so
    /// it is not marked verified on the strength of this login.
    #[tokio::test]
    async fn a_provider_email_change_keeps_the_login_but_proves_nothing() {
        let account = Account::signed_up().await;
        account
            .identities
            .link_identity("google".to_string(), "sub-123".to_string(), email())
            .await
            .unwrap();
        let scheme = JwtScheme::new(
            account.users.clone(),
            jwt_config(),
            HashSetBannedTokenStore::new(),
            account.epochs.clone(),
        )
        .supports_email_verification(account.verified.clone(), MockEmailClient::new())
        .supports_oauth(
            OAuthFlow::new(
                HashMapOAuthStateStore::new(),
                account.identities.clone(),
                MockClient {
                    email: "renamed@example.com".to_string(),
                },
            )
            .with_provider(provider()),
        );

        let outcome = oauth_login(&scheme).await.unwrap();
        let LoginOutcome::Success(token) = outcome else {
            panic!("no 2FA on this account");
        };
        assert!(validates(&scheme, &token).await);
        assert!(!account.verified.is_verified(&email()).await.unwrap());
        assert!(
            account.password_works(SIGNUP_PASSWORD).await,
            "not secured again"
        );
        assert!(
            account
                .users
                .get_user(&Email::try_from(Secret::new("renamed@example.com".to_string())).unwrap())
                .await
                .is_err(),
            "no account made for the new address"
        );
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
        .supports_oauth(flow_for_a_proven_account().await);

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
    async fn a_half_finished_two_factor_login_does_not_survive_a_password_change() {
        use crate::authentication::credential_scheme::PasswordCredentials;
        use tempered_core::SupportsPasswordChange;

        let users = HashMapUserStore::new();
        add_account(&users, SIGNUP_PASSWORD, true).await;
        let codes = HashMapTwoFaCodeStore::new();
        let scheme = JwtScheme::new(
            users.clone(),
            jwt_config(),
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .supports_2fa(codes.clone(), MockEmailClient::new());

        // Someone gets past the password and holds a pending 2FA attempt.
        let outcome = scheme
            .login(PasswordCredentials {
                email: Secret::new("user@example.com".to_string()),
                password: Secret::new(SIGNUP_PASSWORD.to_string()),
            })
            .await
            .unwrap();
        let LoginOutcome::Requires2Fa { attempt_id, .. } = outcome else {
            panic!("expected a 2FA challenge");
        };
        let (_, code) = codes
            .get_login_attempt_id_and_two_fa_code(&email())
            .await
            .unwrap();

        // The password they used is then replaced. The attempt rested on it.
        let new_password = Password::try_from(Secret::new("a-brand-new-password".into())).unwrap();
        scheme.change_password(email(), new_password).await.unwrap();

        assert!(scheme.verify_2fa(email(), attempt_id, code).await.is_err());
    }

    /// A provider that does not vouch for the account's address cannot be
    /// linked to an unproven account: a linked identity counts as proof of
    /// the address, and a squatter could otherwise link their own.
    #[tokio::test]
    async fn a_non_vouching_provider_cannot_be_linked_to_an_unproven_account() {
        let (scheme, users) = scheme_with_oauth();
        let me = Email::try_from(Secret::new("me@example.com".to_string())).unwrap();
        users
            .add_user(User::new(
                me.clone(),
                Password::try_from(Secret::new("my-own-password".to_string())).unwrap(),
                false,
            ))
            .await
            .unwrap();
        let auth = scheme.begin_oauth_link("google", me.clone()).await.unwrap();
        let result = scheme
            .complete_oauth_link("google", "code", &auth.state, &auth.state)
            .await;
        assert!(matches!(result, Err(CredentialError::AddressNotProven)));
        assert!(scheme.oauth_links(&me).await.unwrap().is_empty());
    }

    /// A logged-in user with a proven address links a provider whose
    /// address is not theirs; the provider then logs in to their account.
    #[tokio::test]
    async fn a_linked_provider_logs_in_to_the_account_that_linked_it() {
        let users = HashMapUserStore::new();
        let verified = HashMapEmailVerificationTokenStore::new();
        let scheme = JwtScheme::new(
            users.clone(),
            jwt_config(),
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .supports_email_verification(verified.clone(), MockEmailClient::new())
        .supports_oauth(flow());
        let me = Email::try_from(Secret::new("me@example.com".to_string())).unwrap();
        users
            .add_user(User::new(
                me.clone(),
                Password::try_from(Secret::new("my-own-password".to_string())).unwrap(),
                false,
            ))
            .await
            .unwrap();
        verified.mark_verified(&me).await.unwrap();

        let auth = scheme.begin_oauth_link("google", me.clone()).await.unwrap();
        // A link state does not finish as a login...
        assert!(
            scheme
                .complete_oauth("google", "code", &auth.state, &auth.state)
                .await
                .is_err()
        );
        let auth = scheme.begin_oauth_link("google", me.clone()).await.unwrap();
        let linked = scheme
            .complete_oauth_link("google", "code", &auth.state, &auth.state)
            .await
            .unwrap();
        assert_eq!(linked, me);
        assert_eq!(scheme.oauth_links(&me).await.unwrap(), ["google"]);

        // ...and a login state does not finish as a link.
        let auth = scheme.begin_oauth("google").await.unwrap();
        assert!(
            scheme
                .complete_oauth_link("google", "code", &auth.state, &auth.state)
                .await
                .is_err()
        );

        // The provider (reporting user@example.com) now logs in to me.
        let LoginOutcome::Success(token) = oauth_login(&scheme).await.unwrap() else {
            panic!("no 2FA here");
        };
        assert!(validates(&scheme, &token).await);
        assert!(
            users.get_user(&email()).await.is_err(),
            "no account was made for the provider's address"
        );

        // Unlinked, it is a stranger again.
        assert!(scheme.unlink_oauth(&me, "google").await.unwrap());
        assert!(!scheme.unlink_oauth(&me, "google").await.unwrap());
        assert!(scheme.oauth_links(&me).await.unwrap().is_empty());
    }

    /// An identity already linked to one account cannot be linked to another.
    #[tokio::test]
    async fn an_identity_linked_elsewhere_cannot_be_linked_again() {
        let (scheme, users) = scheme_with_oauth();
        // The provider's own login made the account user@example.com and
        // linked sub-123 to it.
        oauth_login(&scheme).await.unwrap();
        let other = Email::try_from(Secret::new("other@example.com".to_string())).unwrap();
        users
            .add_user(User::new(
                other.clone(),
                Password::try_from(Secret::new("other-password".to_string())).unwrap(),
                false,
            ))
            .await
            .unwrap();
        let auth = scheme
            .begin_oauth_link("google", other.clone())
            .await
            .unwrap();
        let result = scheme
            .complete_oauth_link("google", "code", &auth.state, &auth.state)
            .await;
        assert!(matches!(
            result,
            Err(CredentialError::OAuth(
                crate::oauth::OAuthFlowError::IdentityConflict
            ))
        ));
    }

    /// API keys that whoever signed up an unproven account issued are
    /// removed when a provider login secures it.
    #[tokio::test]
    async fn securing_an_unproven_account_removes_its_api_keys() {
        use crate::persistence::HashMapApiKeyStore;
        use tempered_core::ApiKeyStore;

        let users = HashMapUserStore::new();
        add_account(&users, SIGNUP_PASSWORD, false).await;
        let keys = HashMapApiKeyStore::new();
        let scheme = JwtScheme::new(
            users,
            jwt_config(),
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .supports_api_key_management(keys.clone(), ["read"])
        .supports_oauth(flow());
        scheme
            .issue_user_api_key(email(), vec!["read".to_string()], None)
            .await
            .unwrap();
        assert_eq!(keys.list_for_user(&email()).await.unwrap().len(), 1);

        oauth_login(&scheme).await.unwrap();
        assert!(keys.list_for_user(&email()).await.unwrap().is_empty());
    }

    /// Whoever signed up an unproven account may have added an
    /// authenticator app to it. Securing the account removes that app too,
    /// with the password and passkeys.
    #[tokio::test]
    async fn securing_an_unproven_account_removes_its_authenticator_app() {
        use crate::persistence::HashMapTotpStore;
        use tempered_core::TotpStore;

        let users = HashMapUserStore::new();
        add_account(&users, SIGNUP_PASSWORD, false).await;
        let totp = HashMapTotpStore::new();
        // The squatter's app, already active.
        totp.set_pending(&email(), Secret::new(vec![1; 20]))
            .await
            .unwrap();
        assert!(totp.activate(&email(), 1, vec![[7; 32]]).await.unwrap());

        let scheme = JwtScheme::new(
            users,
            jwt_config(),
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .supports_2fa(HashMapTwoFaCodeStore::new(), MockEmailClient::new())
        .supports_elevation(
            HashSetBannedTokenStore::new(),
            JwtAuthConfig {
                jwt_cookie_name: "elevated".to_string(),
                jwt_secret: Secret::new("another-test-secret-long-enough!".to_string()),
                ..jwt_config()
            },
            |e| e,
        )
        .supports_totp(totp.clone(), "Test")
        .supports_oauth(flow());

        oauth_login(&scheme).await.unwrap();
        assert!(
            totp.active(&email()).await.unwrap().is_none(),
            "the app is gone"
        );
        assert!(
            !totp.use_recovery_code(&email(), &[7; 32]).await.unwrap(),
            "and its codes"
        );
    }

    #[tokio::test]
    async fn oauth_login_to_a_two_factor_account_fails_closed_without_two_factor_support() {
        // The scheme has no 2FA capability, so it cannot challenge this
        // (proven) account, and must not let the login through without it.
        let users = HashMapUserStore::new();
        add_account(&users, "the-users-own-password", true).await;
        let scheme = JwtScheme::new(
            users,
            jwt_config(),
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .supports_oauth(flow_for_a_proven_account().await);

        let result = oauth_login(&scheme).await;
        assert!(matches!(result, Err(CredentialError::TwoFaNotConfigured)));
    }

    #[tokio::test]
    async fn a_provider_address_in_other_case_reaches_the_existing_account() {
        // Signed up as user@example.com, with 2FA; the provider reports
        // User@Example.COM. That is the same account, held to its 2FA (and,
        // with no 2FA capability here, refused), not a fresh second account
        // the provider logs straight into.
        let users = HashMapUserStore::new();
        add_account(&users, "the-users-own-password", true).await;
        let identities = HashMapOAuthIdentityStore::new();
        identities
            .link_identity("github".to_string(), "gh-1".to_string(), email())
            .await
            .unwrap();
        let flow = OAuthFlow::new(
            HashMapOAuthStateStore::new(),
            identities,
            MockClient {
                email: "User@Example.COM".to_string(),
            },
        )
        .with_provider(provider());
        let scheme = JwtScheme::new(
            users,
            jwt_config(),
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .supports_oauth(flow);

        let result = oauth_login(&scheme).await;
        assert!(matches!(result, Err(CredentialError::TwoFaNotConfigured)));
    }

    #[tokio::test]
    async fn two_factor_set_at_an_unverified_signup_does_not_bind_the_owner() {
        // The scheme offers email verification and this address was never
        // confirmed, yet whoever signed up turned 2FA on. The provider's user
        // is not held to it: no challenge, and the requirement is gone.
        let account = Account::signed_up().await;
        account
            .users
            .set_requires_2fa(&email(), true)
            .await
            .unwrap();
        let scheme = account.scheme().await;

        let outcome = oauth_login(&scheme).await.unwrap();
        assert!(matches!(outcome, LoginOutcome::Success(_)));
        assert!(!account.users.get_user(&email()).await.unwrap().requires_2fa);
        assert!(!account.password_works(SIGNUP_PASSWORD).await);
    }

    #[tokio::test]
    async fn without_email_verification_an_unproven_account_keeps_its_two_factor() {
        // No verification capability: the scheme cannot tell a squatter's
        // account from a genuine one. The password still goes, but the second
        // factor stays and the provider login is challenged.
        let users = HashMapUserStore::new();
        add_account(&users, SIGNUP_PASSWORD, true).await;
        let scheme = JwtScheme::new(
            users.clone(),
            jwt_config(),
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .supports_2fa(HashMapTwoFaCodeStore::new(), MockEmailClient::new())
        .supports_oauth(flow());

        let outcome = oauth_login(&scheme).await.unwrap();
        assert!(matches!(outcome, LoginOutcome::Requires2Fa { .. }));
        assert!(users.get_user(&email()).await.unwrap().requires_2fa);

        let password = Password::try_from(Secret::new(SIGNUP_PASSWORD.into())).unwrap();
        assert!(users.authenticate_user(&email(), &password).await.is_err());
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
        assert!(
            cookies
                .iter()
                .any(|c| c.starts_with("__Host-oauth_state=;"))
        );
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
        .supports_oauth(flow_for_a_proven_account().await)
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
        assert!(
            cookies
                .iter()
                .any(|c| c.starts_with("__Host-oauth_state=;"))
        );
        assert!(!cookies.iter().any(|c| c.starts_with("jwt=")));

        // The URL carries only a marker: no email, no attempt id.
        let location = header(&response, "location")[0];
        assert_eq!(location, "/login?step=2fa&oauth_2fa=required#code");

        // The hand-off cookie is short-lived, script-readable, and holds what
        // the page needs to call the 2FA verification route.
        let handoff = cookies
            .iter()
            .find(|c| c.starts_with("__Host-oauth_2fa="))
            .expect("hand-off cookie");
        let (value, attributes) = handoff["__Host-oauth_2fa=".len()..]
            .split_once("; ")
            .unwrap();
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
        AuthValidator, AuthenticationScheme, CredentialId, Email, LoginOutcome, PasskeyCredential,
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
    async fn a_user_lists_renames_and_removes_only_their_own_passkeys() {
        let (scheme, _users) = scheme_with_passkeys().await;
        enroll(&scheme, "cred-a").await;
        enroll(&scheme, "cred-b").await;
        let listed = scheme.passkeys(&email()).await.unwrap();
        assert_eq!(listed.len(), 2);

        let a = tempered_core::CredentialId("cred-a".to_string());
        assert!(
            scheme
                .rename_passkey(&email(), &a, Some("laptop".into()))
                .await
                .unwrap()
        );
        let listed = scheme.passkeys(&email()).await.unwrap();
        assert_eq!(
            listed
                .iter()
                .find(|p| p.id == "cred-a")
                .unwrap()
                .name
                .as_deref(),
            Some("laptop")
        );

        // Someone else's id is "none" to this user.
        let stranger = Email::try_from(Secret::new("stranger@example.com".to_string())).unwrap();
        assert!(!scheme.delete_passkey(&stranger, &a).await.unwrap());
        assert!(!scheme.rename_passkey(&stranger, &a, None).await.unwrap());

        assert!(scheme.delete_passkey(&email(), &a).await.unwrap());
        assert_eq!(scheme.passkeys(&email()).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn register_then_authenticate_issues_a_jwt_that_validates() {
        let (scheme, _users) = scheme_with_passkeys().await;

        enroll(&scheme, "cred-abc").await;

        let ceremony = scheme
            .start_passkey_authentication(Some(email()))
            .await
            .unwrap();
        let LoginOutcome::Success(token) = scheme
            .finish_passkey_authentication(
                ceremony.ceremony_id.clone(),
                reply_with_count(&ceremony, "cred-abc", 1),
            )
            .await
            .unwrap()
        else {
            panic!("no second factor asked by default");
        };

        let parts = http::Request::builder()
            .header("cookie", format!("jwt={}", token.as_str()))
            .body(())
            .unwrap()
            .into_parts()
            .0;
        assert!(scheme.validator().validate(&parts).await.is_ok());
    }

    /// Keeps every 2FA code it is asked to send.
    #[derive(Clone, Default)]
    struct Outbox(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    #[async_trait::async_trait]
    impl tempered_core::EmailClient for Outbox {
        async fn send_email(&self, _: &Email, _: &str, content: &str) -> Result<(), String> {
            self.0.lock().unwrap().push(content.to_string());
            Ok(())
        }
    }

    /// A 2FA account with an enrolled passkey; `hold` turns on
    /// `passkey_login_requires_2fa`. Returns the outcome of a passkey login.
    async fn passkey_login_of_a_2fa_account(
        hold: bool,
        outbox: &Outbox,
    ) -> (
        impl SupportsPasskeys<Token = crate::authentication::token_strategy::JwtToken>
        + tempered_core::SupportsTwoFactor
        + use<>,
        LoginOutcome<crate::authentication::token_strategy::JwtToken>,
    ) {
        let users = HashMapUserStore::new();
        let password = Password::try_from(Secret::new("a-long-password".to_string())).unwrap();
        users
            .add_user(User::new(email(), password, true))
            .await
            .unwrap();
        let flow = PasskeyFlow::new(
            HashMapPasskeyCredentialStore::new(),
            HashMapChallengeStore::new(),
            MockVerifier,
        );
        let scheme = JwtScheme::new(
            users,
            jwt_config(),
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .supports_2fa(
            crate::persistence::HashMapTwoFaCodeStore::new(),
            outbox.clone(),
        )
        .supports_passkeys(flow);
        let scheme = if hold {
            scheme.passkey_login_requires_2fa()
        } else {
            scheme
        };

        let ceremony = scheme.start_passkey_registration(email()).await.unwrap();
        let response = reply_with_count(&ceremony, "cred-abc", 0);
        scheme
            .finish_passkey_registration(email(), ceremony.ceremony_id, response)
            .await
            .unwrap();
        let ceremony = scheme.start_passkey_authentication(None).await.unwrap();
        let outcome = scheme
            .finish_passkey_authentication(
                ceremony.ceremony_id.clone(),
                reply_with_count(&ceremony, "cred-abc", 1),
            )
            .await
            .unwrap();
        (scheme, outcome)
    }

    #[tokio::test]
    async fn by_default_a_passkey_stands_in_for_both_factors() {
        let outbox = Outbox::default();
        let (_, outcome) = passkey_login_of_a_2fa_account(false, &outbox).await;
        assert!(matches!(outcome, LoginOutcome::Success(_)));
        assert!(outbox.0.lock().unwrap().is_empty(), "no code sent");
    }

    #[tokio::test]
    async fn a_scheme_can_hold_passkey_logins_to_the_second_factor() {
        let outbox = Outbox::default();
        let (scheme, outcome) = passkey_login_of_a_2fa_account(true, &outbox).await;
        let LoginOutcome::Requires2Fa {
            email: who,
            attempt_id,
        } = outcome
        else {
            panic!("a 2FA account is asked for its code");
        };
        assert_eq!(who, email());

        let code = tempered_core::TwoFaCode::parse(outbox.0.lock().unwrap()[0].clone()).unwrap();
        let token = tempered_core::SupportsTwoFactor::verify_2fa(&scheme, who, attempt_id, code)
            .await
            .unwrap();
        assert!(!token.as_str().is_empty());
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

    #[tokio::test]
    async fn an_enrolment_started_before_the_account_was_deleted_cannot_finish() {
        let (scheme, users) = scheme_with_passkeys().await;
        // Begun from a session of the old account...
        let ceremony = scheme.start_passkey_registration(email()).await.unwrap();

        scheme.delete_account(email()).await.unwrap();
        let password = Password::try_from(Secret::new("another-password".to_string())).unwrap();
        users
            .add_user(User::new(email(), password, false))
            .await
            .unwrap();

        // ...it must not add a passkey to the account that reuses the address.
        let response = reply_with_count(&ceremony, "cred-abc", 0);
        let result = scheme
            .finish_passkey_registration(email(), ceremony.ceremony_id, response)
            .await;
        assert!(matches!(
            result,
            Err(CredentialError::Passkey(PasskeyFlowError::Challenge(
                tempered_core::ChallengeStoreError::ChallengeNotFound
            )))
        ));
    }

    #[tokio::test]
    async fn an_enrolment_for_an_address_with_no_account_cannot_finish() {
        let (scheme, users) = scheme_with_passkeys().await;
        let ceremony = scheme.start_passkey_registration(email()).await.unwrap();
        // The account went away (moved, or deleted by a store of the app's
        // own) without the passkey cleanup.
        users.delete_user(&email()).await.unwrap();

        let response = reply_with_count(&ceremony, "cred-abc", 0);
        assert!(
            scheme
                .finish_passkey_registration(email(), ceremony.ceremony_id, response)
                .await
                .is_err()
        );
        assert!(scheme.passkeys(&email()).await.unwrap().is_empty());
    }

    // Paused time: the scheme's short wait for the lock passes instantly.
    #[tokio::test(start_paused = true)]
    async fn nothing_logs_in_or_enrols_while_the_credentials_are_locked() {
        use crate::authentication::token_strategy::{JwtTokenError, TokenStrategy};

        let (scheme, _users) = scheme_with_passkeys().await;
        enroll(&scheme, "cred-abc").await;
        let enrolment = scheme.start_passkey_registration(email()).await.unwrap();
        let login = scheme
            .start_passkey_authentication(Some(email()))
            .await
            .unwrap();

        // Someone is removing this user's credentials.
        let lock = scheme
            .token_strategy()
            .lock_user(&email())
            .await
            .unwrap()
            .expect("free");

        let result = scheme
            .finish_passkey_registration(
                email(),
                enrolment.ceremony_id.clone(),
                reply_with_count(&enrolment, "cred-new", 0),
            )
            .await;
        assert!(matches!(result, Err(CredentialError::AccountBusy)));

        let result = scheme
            .finish_passkey_authentication(
                login.ceremony_id.clone(),
                reply_with_count(&login, "cred-abc", 1),
            )
            .await;
        assert!(matches!(
            result,
            Err(CredentialError::Token(JwtTokenError::Locked))
        ));

        let result = scheme
            .login(
                crate::authentication::credential_scheme::PasswordCredentials {
                    email: Secret::new("user@example.com".to_string()),
                    password: Secret::new("a-long-password".to_string()),
                },
            )
            .await;
        assert!(matches!(
            result,
            Err(CredentialError::Token(JwtTokenError::Locked))
        ));

        // Deletion waits for the lock too, and gives up rather than run
        // alongside the other holder.
        assert!(matches!(
            scheme.delete_account(email()).await,
            Err(CredentialError::AccountBusy)
        ));

        // Released, everything works again.
        scheme
            .token_strategy()
            .unlock_user(&email(), lock)
            .await
            .unwrap();
        enroll(&scheme, "cred-new").await;
    }

    /// A credential store that is down: every call fails.
    #[derive(Clone)]
    struct UnavailableCredentialStore;

    #[async_trait::async_trait]
    impl PasskeyCredentialStore for UnavailableCredentialStore {
        async fn add_credential(&self, _: PasskeyCredential) -> Result<(), PasskeyStoreError> {
            Err(PasskeyStoreError::UnexpectedError("down".into()))
        }
        async fn delete_credential(
            &self,
            _: &Email,
            _: &CredentialId,
        ) -> Result<bool, PasskeyStoreError> {
            Err(PasskeyStoreError::UnexpectedError("down".into()))
        }
        async fn rename_credential(
            &self,
            _: &Email,
            _: &CredentialId,
            _: Option<String>,
        ) -> Result<bool, PasskeyStoreError> {
            Err(PasskeyStoreError::UnexpectedError("down".into()))
        }
        async fn reassign(&self, _: &Email, _: &Email) -> Result<(), PasskeyStoreError> {
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

        // The failed deletion released its lock: the user can still log in.
        let outcome = scheme
            .login(
                crate::authentication::credential_scheme::PasswordCredentials {
                    email: Secret::new("user@example.com".to_string()),
                    password: Secret::new("a-long-password".to_string()),
                },
            )
            .await;
        assert!(outcome.is_ok());
    }
}

#[cfg(test)]
mod email_verification_tests {
    use std::sync::{Arc, Mutex};

    use super::JwtScheme;
    use crate::auth_validation::local_jwt_validator::JwtAuthConfig;
    use crate::authentication::credential_scheme::{PasswordCredentials, RegistrationData};
    use crate::persistence::{
        HashMapEmailVerificationTokenStore, HashMapTokenEpochStore, HashMapUserStore,
        HashSetBannedTokenStore,
    };
    use secrecy::Secret;
    use tempered_core::{
        AuthenticationScheme, Email, EmailClient, LoginOutcome, Password,
        RequiresEmailVerification, strategies::authenticator::SupportsRegistration,
    };

    /// Keeps every message it is asked to send.
    #[derive(Clone, Default)]
    struct Outbox(Arc<Mutex<Vec<String>>>);

    impl Outbox {
        /// Mail `n` (from 0), waiting for it: signup and reset mails go out
        /// after the call returns (`authentication::deferred`).
        async fn mail(&self, n: usize) -> String {
            for _ in 0..1000 {
                if let Some(mail) = self.0.lock().unwrap().get(n).cloned() {
                    return mail;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            panic!("mail {n} was never sent");
        }
    }

    #[async_trait::async_trait]
    impl EmailClient for Outbox {
        async fn send_email(&self, _: &Email, _: &str, content: &str) -> Result<(), String> {
            self.0.lock().unwrap().push(content.to_string());
            Ok(())
        }
    }

    fn email() -> Email {
        Email::try_from(Secret::new("user@example.com".to_string())).unwrap()
    }

    #[tokio::test]
    async fn signup_sends_the_verification_link_and_resending_stops_once_verified() {
        let outbox = Outbox::default();
        let scheme = JwtScheme::new(
            HashMapUserStore::new(),
            JwtAuthConfig {
                jwt_cookie_name: "jwt".to_string(),
                jwt_secret: Secret::new("a-test-secret-that-is-long-enough".to_string()),
                token_ttl_in_seconds: 3600,
                audience: None,
                issuer: None,
            },
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .supports_registration()
        .supports_email_verification(HashMapEmailVerificationTokenStore::new(), outbox.clone());

        let password = Password::try_from(Secret::new("a-long-password".to_string())).unwrap();
        scheme
            .register(
                email(),
                password,
                RegistrationData {
                    requires_2fa: false,
                },
            )
            .await
            .unwrap();

        let link = outbox.mail(0).await;
        assert_eq!(
            outbox.0.lock().unwrap().len(),
            1,
            "signup sends one verification link"
        );
        scheme.verify_email(&email(), link).await.unwrap();
        assert!(scheme.is_email_verified(&email()).await.unwrap());

        // Asking again for a verified address sends nothing.
        scheme.initiate_email_verification(email()).await.unwrap();
        assert_eq!(outbox.0.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn signup_for_a_taken_address_mails_its_owner_and_changes_nothing() {
        let outbox = Outbox::default();
        let scheme = JwtScheme::new(
            HashMapUserStore::new(),
            JwtAuthConfig {
                jwt_cookie_name: "jwt".to_string(),
                jwt_secret: Secret::new("a-test-secret-that-is-long-enough".to_string()),
                token_ttl_in_seconds: 3600,
                audience: None,
                issuer: None,
            },
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .supports_registration()
        .supports_email_verification(HashMapEmailVerificationTokenStore::new(), outbox.clone());
        let signup = |password: &str| {
            let password = Password::try_from(Secret::new(password.to_string())).unwrap();
            scheme.register(
                email(),
                password,
                RegistrationData {
                    requires_2fa: false,
                },
            )
        };

        signup("a-long-password").await.unwrap();
        // The second signup succeeds as far as the caller can tell.
        signup("someone-elses-password").await.unwrap();

        // A verification link, then the notice.
        outbox.mail(0).await;
        assert_eq!(
            outbox.mail(1).await,
            tempered_core::Mail::AlreadyRegistered.text()
        );
        let original = PasswordCredentials {
            email: Secret::new("user@example.com".to_string()),
            password: Secret::new("a-long-password".to_string()),
        };
        assert!(matches!(
            scheme.login(original).await,
            Ok(LoginOutcome::Success(_))
        ));
    }

    #[tokio::test]
    async fn a_token_verifies_only_the_account_it_was_sent_to() {
        let outbox = Outbox::default();
        let scheme = JwtScheme::new(
            HashMapUserStore::new(),
            JwtAuthConfig {
                jwt_cookie_name: "jwt".to_string(),
                jwt_secret: Secret::new("a-test-secret-that-is-long-enough".to_string()),
                token_ttl_in_seconds: 3600,
                audience: None,
                issuer: None,
            },
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .supports_email_verification(HashMapEmailVerificationTokenStore::new(), outbox.clone());

        // The owner of the inbox, logged in to an account of their own, opens
        // a link that was sent for the account someone else created.
        scheme.initiate_email_verification(email()).await.unwrap();
        let token = outbox.0.lock().unwrap()[0].clone();
        let other = Email::try_from(Secret::new("other@example.com".to_string())).unwrap();

        assert!(scheme.verify_email(&other, token.clone()).await.is_err());
        assert!(!scheme.is_email_verified(&other).await.unwrap());
        assert!(!scheme.is_email_verified(&email()).await.unwrap());
        // And the token is spent.
        assert!(scheme.verify_email(&email(), token).await.is_err());
    }
}

#[cfg(test)]
mod password_reset_tests {
    use std::sync::{Arc, Mutex};

    use super::JwtScheme;
    use crate::auth_validation::local_jwt_validator::JwtAuthConfig;
    use crate::authentication::credential_scheme::RegistrationData;
    use crate::persistence::{
        HashMapPasswordResetTokenStore, HashMapTokenEpochStore, HashMapUserStore,
        HashSetBannedTokenStore,
    };
    use secrecy::Secret;
    use tempered_core::{
        Email, EmailClient, Password, SupportsAccountDeletion, SupportsPasswordChange,
        SupportsPasswordReset, strategies::authenticator::SupportsRegistration,
    };

    /// Keeps every message it is asked to send (the reset token is the body).
    #[derive(Clone, Default)]
    struct Outbox(Arc<Mutex<Vec<String>>>);

    impl Outbox {
        /// Mail `n` (from 0), waiting for it: signup and reset mails go out
        /// after the call returns (`authentication::deferred`).
        async fn mail(&self, n: usize) -> String {
            for _ in 0..1000 {
                if let Some(mail) = self.0.lock().unwrap().get(n).cloned() {
                    return mail;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            panic!("mail {n} was never sent");
        }
    }

    #[async_trait::async_trait]
    impl EmailClient for Outbox {
        async fn send_email(&self, _: &Email, _: &str, content: &str) -> Result<(), String> {
            self.0.lock().unwrap().push(content.to_string());
            Ok(())
        }
    }

    fn email() -> Email {
        Email::try_from(Secret::new("user@example.com".to_string())).unwrap()
    }

    fn password(p: &str) -> Password {
        Password::try_from(Secret::new(p.to_string())).unwrap()
    }

    fn scheme(
        outbox: &Outbox,
    ) -> impl SupportsRegistration<RegistrationData = RegistrationData>
    + SupportsPasswordReset
    + SupportsPasswordChange
    + SupportsAccountDeletion {
        JwtScheme::new(
            HashMapUserStore::new(),
            JwtAuthConfig {
                jwt_cookie_name: "jwt".to_string(),
                jwt_secret: Secret::new("a-test-secret-that-is-long-enough".to_string()),
                token_ttl_in_seconds: 3600,
                audience: None,
                issuer: None,
            },
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .supports_registration()
        .supports_password_reset(HashMapPasswordResetTokenStore::new(), outbox.clone())
    }

    async fn sign_up(
        scheme: &impl SupportsRegistration<RegistrationData = RegistrationData>,
        with: &str,
    ) {
        let data = RegistrationData {
            requires_2fa: false,
        };
        scheme
            .register(email(), password(with), data)
            .await
            .unwrap();
    }

    /// An email client that holds every send until released.
    #[derive(Clone)]
    struct Stalled(Arc<tokio::sync::Notify>, Outbox);

    #[async_trait::async_trait]
    impl EmailClient for Stalled {
        async fn send_email(&self, to: &Email, subject: &str, body: &str) -> Result<(), String> {
            self.0.notified().await;
            self.1.send_email(to, subject, body).await
        }
    }

    /// The call answers before the account lookup and the mail, so a real
    /// address takes no longer than an unknown one.
    #[tokio::test]
    async fn initiating_a_reset_does_not_wait_for_the_mail() {
        let release = Arc::new(tokio::sync::Notify::new());
        let outbox = Outbox::default();
        let scheme = JwtScheme::new(
            HashMapUserStore::new(),
            JwtAuthConfig {
                jwt_cookie_name: "jwt".to_string(),
                jwt_secret: Secret::new("a-test-secret-that-is-long-enough".to_string()),
                token_ttl_in_seconds: 3600,
                audience: None,
                issuer: None,
            },
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .supports_registration()
        .supports_password_reset(
            HashMapPasswordResetTokenStore::new(),
            Stalled(release.clone(), outbox.clone()),
        );
        sign_up(&scheme, "the-original-password").await;

        // Returns although the mail cannot go out yet.
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            scheme.initiate_password_reset(email()),
        )
        .await
        .expect("answered without waiting for the mail")
        .unwrap();
        assert!(outbox.0.lock().unwrap().is_empty());

        release.notify_one();
        let link = outbox.mail(0).await;
        scheme
            .complete_password_reset(link, password("the-new-password"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_reset_link_dies_with_the_account() {
        // The old owner asks for a reset, then deletes the account; someone
        // else signs up with the address. The link in the old mailbox must
        // not set the new account's password.
        let outbox = Outbox::default();
        let scheme = scheme(&outbox);
        sign_up(&scheme, "the-first-owners-password").await;
        scheme.initiate_password_reset(email()).await.unwrap();
        let link = outbox.mail(0).await;

        scheme.delete_account(email()).await.unwrap();
        sign_up(&scheme, "the-new-owners-password").await;

        let result = scheme
            .complete_password_reset(link, password("chosen-by-the-old-owner"))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn a_password_change_voids_outstanding_reset_links() {
        let outbox = Outbox::default();
        let scheme = scheme(&outbox);
        sign_up(&scheme, "the-original-password").await;
        scheme.initiate_password_reset(email()).await.unwrap();
        let link = outbox.mail(0).await;

        scheme
            .change_password(email(), password("a-fresh-password"))
            .await
            .unwrap();

        let result = scheme
            .complete_password_reset(link, password("an-intruders-password"))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn a_completed_reset_voids_the_other_links() {
        let outbox = Outbox::default();
        let scheme = scheme(&outbox);
        sign_up(&scheme, "the-original-password").await;
        scheme.initiate_password_reset(email()).await.unwrap();
        let first = outbox.mail(0).await;
        scheme.initiate_password_reset(email()).await.unwrap();
        let second = outbox.mail(1).await;

        scheme
            .complete_password_reset(second, password("the-new-password"))
            .await
            .unwrap();
        let result = scheme
            .complete_password_reset(first, password("another-password"))
            .await;
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod config_tests {
    use super::JwtScheme;
    use crate::auth_validation::local_jwt_validator::JwtAuthConfig;
    use crate::persistence::{HashMapTokenEpochStore, HashMapUserStore, HashSetBannedTokenStore};
    use secrecy::Secret;

    fn config(cookie: &str) -> JwtAuthConfig {
        JwtAuthConfig {
            jwt_cookie_name: cookie.to_string(),
            jwt_secret: Secret::new("a-test-secret-that-is-long-enough".to_string()),
            token_ttl_in_seconds: 3600,
            audience: None,
            issuer: None,
        }
    }

    #[test]
    #[should_panic(expected = "uses the primary JWT secret")]
    fn elevation_with_the_login_secret_is_refused_at_startup() {
        // Same secret, no aud/iss: every login token would pass as elevated.
        let _ = JwtScheme::new(
            HashMapUserStore::new(),
            config("jwt"),
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .supports_elevation(
            HashSetBannedTokenStore::new(),
            config("elevated_jwt"),
            |e| e,
        );
    }
}

#[cfg(test)]
mod totp_tests {
    use std::sync::{Arc, Mutex};

    use super::JwtScheme;
    use crate::auth_validation::local_jwt_validator::JwtAuthConfig;
    use crate::authentication::credential_scheme::PasswordCredentials;
    use crate::authentication::totp::code_for;
    use crate::persistence::{
        HashMapTokenEpochStore, HashMapTotpStore, HashMapTwoFaCodeStore, HashMapUserStore,
        HashSetBannedTokenStore,
    };
    use secrecy::{ExposeSecret, Secret};
    use tempered_core::{
        AuthenticationScheme, Email, EmailClient, LoginOutcome, SupportsAccountDeletion,
        SupportsTotp, SupportsTwoFactor, TotpStore, TwoFaAttemptId, TwoFaCode, User, UserStore,
    };

    /// Keeps every message it is asked to send.
    #[derive(Clone, Default)]
    struct Outbox(Arc<Mutex<Vec<String>>>);

    #[async_trait::async_trait]
    impl EmailClient for Outbox {
        async fn send_email(&self, _: &Email, _: &str, content: &str) -> Result<(), String> {
            self.0.lock().unwrap().push(content.to_string());
            Ok(())
        }
    }

    fn config(cookie: &str, secret: &str) -> JwtAuthConfig {
        JwtAuthConfig {
            jwt_cookie_name: cookie.to_string(),
            jwt_secret: Secret::new(secret.to_string()),
            token_ttl_in_seconds: 3600,
            audience: None,
            issuer: None,
        }
    }

    fn email() -> Email {
        Email::try_from(Secret::new("user@example.com".to_string())).unwrap()
    }

    struct Setup<S> {
        scheme: S,
        outbox: Outbox,
        totp: HashMapTotpStore,
        users: HashMapUserStore,
        epochs: HashMapTokenEpochStore,
    }

    async fn setup()
    -> Setup<impl SupportsTotp<Credentials = PasswordCredentials> + SupportsAccountDeletion + Clone>
    {
        let users = HashMapUserStore::new();
        users
            .add_user(
                User::parse(
                    email().as_ref().clone(),
                    Secret::new("passwordpassword".into()),
                    false,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let outbox = Outbox::default();
        let totp = HashMapTotpStore::new();
        let epochs = HashMapTokenEpochStore::new();
        let scheme = JwtScheme::new(
            users.clone(),
            config("jwt", "a-test-secret-that-is-long-enough"),
            HashSetBannedTokenStore::new(),
            epochs.clone(),
        )
        .supports_2fa(HashMapTwoFaCodeStore::new(), outbox.clone())
        .supports_elevation(
            HashSetBannedTokenStore::new(),
            config("elevated", "another-test-secret-long-enough!"),
            |e| e.supports_account_deletion(),
        )
        .supports_totp(totp.clone(), "Test App");
        Setup {
            scheme,
            outbox,
            totp,
            users,
            epochs,
        }
    }

    fn credentials() -> PasswordCredentials {
        PasswordCredentials {
            email: Secret::new("user@example.com".to_string()),
            password: Secret::new("passwordpassword".to_string()),
        }
    }

    async fn second_step<S>(scheme: &S) -> TwoFaAttemptId
    where
        S: AuthenticationScheme<Credentials = PasswordCredentials>,
        S::AuthError: std::fmt::Debug,
    {
        match scheme.login(credentials()).await.unwrap() {
            LoginOutcome::Requires2Fa { attempt_id, .. } => attempt_id,
            LoginOutcome::Success(_) => panic!("2FA was not asked for"),
        }
    }

    /// Enrol and confirm an app; returns its secret and the recovery codes.
    async fn enrol<S: SupportsTotp>(scheme: &S, totp: &HashMapTotpStore) -> (Vec<u8>, Vec<String>) {
        let enrollment = scheme.start_totp(email()).await.ok().unwrap();
        assert!(
            enrollment
                .otpauth_uri
                .expose_secret()
                .starts_with("otpauth://totp/Test%20App%3A")
        );
        let secret = totp
            .pending(&email())
            .await
            .unwrap()
            .unwrap()
            .expose_secret()
            .clone();
        let codes = scheme
            .confirm_totp(email(), code_for(&secret, 0))
            .await
            .ok()
            .unwrap();
        (secret, codes)
    }

    #[tokio::test]
    async fn an_app_replaces_mailed_codes_and_recovery_codes_work_once() {
        let s = setup().await;
        let (secret, recovery) = enrol(&s.scheme, &s.totp).await;
        assert_eq!(recovery.len(), 10);
        assert!(
            s.users.get_user(&email()).await.unwrap().requires_2fa(),
            "2FA is on"
        );

        // The login asks for a second factor, and mails nothing.
        let attempt = second_step(&s.scheme).await;
        assert!(s.outbox.0.lock().unwrap().is_empty());
        let next = code_for(&secret, 1);
        assert!(
            s.scheme
                .verify_2fa(email(), attempt, next.clone())
                .await
                .is_ok()
        );

        // The same code again is a replay.
        let attempt = second_step(&s.scheme).await;
        assert!(s.scheme.verify_2fa(email(), attempt, next).await.is_err());

        // A recovery code works once, typed any way.
        let attempt = second_step(&s.scheme).await;
        let first = TwoFaCode::parse(recovery[0].clone()).unwrap();
        assert!(
            s.scheme
                .verify_2fa(email(), attempt, first.clone())
                .await
                .is_ok()
        );
        let attempt = second_step(&s.scheme).await;
        assert!(s.scheme.verify_2fa(email(), attempt, first).await.is_err());
        let attempt = second_step(&s.scheme).await;
        let typed = TwoFaCode::parse(recovery[1].to_uppercase().replace('-', "")).unwrap();
        assert!(s.scheme.verify_2fa(email(), attempt, typed).await.is_ok());
    }

    #[tokio::test]
    async fn wrong_app_codes_use_up_the_attempt() {
        let s = setup().await;
        let (secret, _) = enrol(&s.scheme, &s.totp).await;
        let attempt = second_step(&s.scheme).await;
        let wrong = TwoFaCode::parse("000000".to_string()).unwrap();
        let wrong = if wrong == code_for(&secret, 1) || wrong == code_for(&secret, 0) {
            TwoFaCode::parse("111111".to_string()).unwrap()
        } else {
            wrong
        };
        let mut refused = 0;
        for _ in 0..20 {
            if s.scheme
                .verify_2fa(email(), attempt.clone(), wrong.clone())
                .await
                .is_err()
            {
                refused += 1;
            }
        }
        assert_eq!(refused, 20);
        // The budget is spent: now even the right code is refused.
        let right = code_for(&secret, 1);
        assert!(s.scheme.verify_2fa(email(), attempt, right).await.is_err());
    }

    #[tokio::test]
    async fn a_confirmation_needs_a_code_from_the_pending_app() {
        let s = setup().await;
        s.scheme.start_totp(email()).await.ok().unwrap();
        let wrong = TwoFaCode::parse("123456".to_string()).unwrap();
        // (One in a million: the wrong code is right. Then this test proves less.)
        let _ = s.scheme.confirm_totp(email(), wrong).await;
        if s.totp.active(&email()).await.unwrap().is_none() {
            assert!(
                s.totp.pending(&email()).await.unwrap().is_some(),
                "still pending"
            );
            assert!(!s.users.get_user(&email()).await.unwrap().requires_2fa());
        }
        // Nothing to confirm without a start.
        let other = setup().await;
        let code = TwoFaCode::parse("123456".to_string()).unwrap();
        assert!(other.scheme.confirm_totp(email(), code).await.is_err());
    }

    #[tokio::test]
    async fn disabling_the_app_brings_back_mailed_codes() {
        let s = setup().await;
        enrol(&s.scheme, &s.totp).await;
        s.scheme.disable_totp(email()).await.ok().unwrap();

        let attempt = second_step(&s.scheme).await;
        let mailed = s
            .outbox
            .0
            .lock()
            .unwrap()
            .first()
            .cloned()
            .expect("a mailed code");
        let code = TwoFaCode::parse(mailed).unwrap();
        assert!(s.scheme.verify_2fa(email(), attempt, code).await.is_ok());
    }

    #[tokio::test]
    async fn new_recovery_codes_replace_the_old_ones() {
        let s = setup().await;
        let (_, old) = enrol(&s.scheme, &s.totp).await;
        let new = s
            .scheme
            .regenerate_recovery_codes(email())
            .await
            .ok()
            .unwrap();

        let attempt = second_step(&s.scheme).await;
        let stale = TwoFaCode::parse(old[0].clone()).unwrap();
        assert!(s.scheme.verify_2fa(email(), attempt, stale).await.is_err());
        let attempt = second_step(&s.scheme).await;
        let fresh = TwoFaCode::parse(new[0].clone()).unwrap();
        assert!(s.scheme.verify_2fa(email(), attempt, fresh).await.is_ok());
    }

    /// Confirming an app and removing the user's credentials exclude each
    /// other: while someone holds the credential lock (an account deletion,
    /// or a provider login securing the account), no app is confirmed.
    #[tokio::test]
    async fn an_app_is_not_confirmed_while_the_credentials_are_locked() {
        use tempered_core::TokenEpochStore;
        let s = setup().await;
        s.scheme.start_totp(email()).await.ok().unwrap();
        let secret = s
            .totp
            .pending(&email())
            .await
            .unwrap()
            .unwrap()
            .expose_secret()
            .clone();
        assert!(
            s.epochs
                .try_lock_user(&email(), "cleanup", 30)
                .await
                .unwrap()
        );

        let result = s.scheme.confirm_totp(email(), code_for(&secret, 0)).await;
        assert!(result.is_err());
        assert!(s.totp.active(&email()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn deleting_the_account_forgets_the_app() {
        let s = setup().await;
        enrol(&s.scheme, &s.totp).await;
        s.scheme.delete_account(email()).await.ok().unwrap();
        assert!(s.totp.active(&email()).await.unwrap().is_none());
    }
}

/// The customisation hooks: typed mail, audit events, the deferred runner
/// and the app's own JWT claims.
#[cfg(test)]
mod customisation_tests {
    use std::sync::{Arc, Mutex};

    use super::JwtScheme;
    use crate::auth_validation::local_jwt_validator::JwtAuthConfig;
    use crate::authentication::credential_scheme::PasswordCredentials;
    use crate::authentication::deferred::{DeferredJob, DeferredRunner};
    use crate::authentication::token_strategy::ClaimsProvider;
    use crate::endpoints::{
        AuthEvent, AuthEventSink, EndpointRequest, Endpoints, PathOverrides, RouteId,
    };
    use crate::persistence::{
        HashMapPasswordResetTokenStore, HashMapTokenEpochStore, HashMapUserStore,
        HashSetBannedTokenStore,
    };
    use secrecy::Secret;
    use tempered_core::{
        AuthValidator, AuthenticationScheme, Email, EmailClient, LoginOutcome, Mail,
        SupportsPasswordReset, User, UserStore,
    };

    fn config() -> JwtAuthConfig {
        JwtAuthConfig {
            jwt_cookie_name: "jwt".to_string(),
            jwt_secret: Secret::new("a-test-secret-that-is-long-enough".to_string()),
            token_ttl_in_seconds: 300,
            audience: None,
            issuer: None,
        }
    }

    fn email() -> Email {
        Email::try_from(Secret::new("user@example.com".to_string())).unwrap()
    }

    async fn users() -> HashMapUserStore {
        let users = HashMapUserStore::new();
        users
            .add_user(
                User::parse(
                    email().as_ref().clone(),
                    Secret::new("passwordpassword".into()),
                    false,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        users
    }

    /// Keeps the typed messages; renders nothing.
    #[derive(Clone, Default)]
    struct Typed(Arc<Mutex<Vec<Mail>>>);

    #[async_trait::async_trait]
    impl EmailClient for Typed {
        async fn send_email(&self, _: &Email, _: &str, _: &str) -> Result<(), String> {
            unreachable!("send_mail is overridden")
        }
        async fn send_mail(&self, _: &Email, mail: Mail) -> Result<(), String> {
            self.0.lock().unwrap().push(mail);
            Ok(())
        }
    }

    /// Runs jobs on its own, counting them.
    #[derive(Clone, Default)]
    struct Counting(Arc<Mutex<Vec<&'static str>>>);

    impl DeferredRunner for Counting {
        fn run(&self, what: &'static str, job: DeferredJob) {
            self.0.lock().unwrap().push(what);
            tokio::spawn(job);
        }
    }

    #[tokio::test]
    async fn mail_arrives_typed_through_the_apps_runner() {
        let mail = Typed::default();
        let runner = Counting::default();
        let scheme = JwtScheme::new(
            users().await,
            config(),
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .supports_password_reset(HashMapPasswordResetTokenStore::new(), mail.clone())
        .deferred_runner(runner.clone());

        scheme.initiate_password_reset(email()).await.unwrap();
        for _ in 0..200 {
            if !mail.0.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        assert_eq!(*runner.0.lock().unwrap(), ["password reset mail"]);
        let sent = mail.0.lock().unwrap().clone();
        assert!(matches!(sent.as_slice(), [Mail::PasswordReset { token }] if !token.is_empty()));
        assert_eq!(
            format!("{:?}", sent[0]),
            "PasswordReset",
            "Debug shows no token"
        );
    }

    #[derive(Clone, Default)]
    struct Recorded(Arc<Mutex<Vec<AuthEvent>>>);

    #[async_trait::async_trait]
    impl AuthEventSink for Recorded {
        async fn record(&self, event: AuthEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    #[tokio::test]
    async fn every_request_is_reported_with_its_account_and_status() {
        let events = Recorded::default();
        let scheme = JwtScheme::new(
            users().await,
            config(),
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .auth_events(events.clone());
        let spec = scheme
            .routes(&PathOverrides::default())
            .into_iter()
            .find(|r| r.id == RouteId::Login)
            .unwrap();
        let body = serde_json::json!({ "email": "user@example.com", "password": "wrong-password" });
        let request = EndpointRequest::new(
            http::Request::post("/login")
                .header("content-type", "application/json")
                .body(())
                .unwrap()
                .into_parts()
                .0,
            bytes::Bytes::from(body.to_string()),
            Vec::new(),
        );
        let response = scheme.handle(&spec, request).await;
        let recorded = events.0.lock().unwrap().clone();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].route, RouteId::Login);
        assert_eq!(recorded[0].status, response.status().as_u16());
        assert_eq!(recorded[0].account, Some(email()));
    }

    struct Roles;

    #[async_trait::async_trait]
    impl ClaimsProvider for Roles {
        async fn claims(&self, _: &Email) -> serde_json::Map<String, serde_json::Value> {
            serde_json::json!({ "role": "editor" })
                .as_object()
                .unwrap()
                .clone()
        }
    }

    #[tokio::test]
    async fn the_apps_claims_ride_in_the_jwt() {
        let scheme = JwtScheme::new(
            users().await,
            config(),
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .jwt_claims(Roles);
        let credentials = PasswordCredentials {
            email: Secret::new("user@example.com".to_string()),
            password: Secret::new("passwordpassword".to_string()),
        };
        let LoginOutcome::Success(token) = scheme.login(credentials).await.unwrap() else {
            panic!("no 2FA");
        };
        let parts = http::Request::builder()
            .header("cookie", format!("jwt={}", token.as_str()))
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let claims = scheme.validator().validate(&parts).await.unwrap();
        assert_eq!(claims.ext.unwrap()["role"], "editor");
    }
}

#[cfg(test)]
mod email_change_tests {
    use std::sync::{Arc, Mutex};

    use super::{JwtScheme, JwtToken};
    use crate::auth_validation::local_jwt_validator::JwtAuthConfig;
    use crate::authentication::credential_scheme::{PasswordCredentials, RegistrationData};
    use crate::persistence::{
        HashMapEmailChangeStore, HashMapEmailVerificationTokenStore, HashMapTokenEpochStore,
        HashMapUserStore, HashSetBannedTokenStore,
    };
    use secrecy::{ExposeSecret, Secret};
    use tempered_core::{
        AuthValidator, AuthenticationScheme, Email, EmailClient, LoginOutcome, Mail, Password,
        RequiresEmailVerification, SupportsEmailChange, UserStore,
        strategies::authenticator::SupportsRegistration,
    };

    /// Keeps every mail with its recipient.
    #[derive(Clone, Default)]
    struct Outbox(Arc<Mutex<Vec<(String, Mail)>>>);

    impl Outbox {
        /// The first mail to `to` that `pick` accepts, waiting for it (the
        /// mails go out after the call returns).
        async fn find<T>(&self, to: &str, pick: impl Fn(&Mail) -> Option<T>) -> T {
            for _ in 0..1000 {
                let found = self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|(r, _)| r == to)
                    .find_map(|(_, m)| pick(m));
                if let Some(found) = found {
                    return found;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            panic!("no such mail to {to}");
        }

        fn count(&self) -> usize {
            self.0.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl EmailClient for Outbox {
        async fn send_email(&self, _: &Email, _: &str, _: &str) -> Result<(), String> {
            unreachable!("the scheme sends typed mail")
        }
        async fn send_mail(&self, to: &Email, mail: Mail) -> Result<(), String> {
            self.0
                .lock()
                .unwrap()
                .push((to.as_ref().expose_secret().clone(), mail));
            Ok(())
        }
    }

    fn email(s: &str) -> Email {
        Email::try_from(Secret::new(s.to_string())).unwrap()
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
    async fn a_confirmed_change_moves_the_account_and_ends_its_sessions() {
        let outbox = Outbox::default();
        let users = HashMapUserStore::new();
        let scheme = JwtScheme::new(
            users.clone(),
            JwtAuthConfig {
                jwt_cookie_name: "jwt".to_string(),
                jwt_secret: Secret::new("a-test-secret-that-is-long-enough".to_string()),
                token_ttl_in_seconds: 3600,
                audience: None,
                issuer: None,
            },
            HashSetBannedTokenStore::new(),
            HashMapTokenEpochStore::new(),
        )
        .supports_registration()
        .supports_email_verification(HashMapEmailVerificationTokenStore::new(), outbox.clone())
        .supports_email_change(HashMapEmailChangeStore::new());

        let password = Password::try_from(Secret::new("a-long-password".to_string())).unwrap();
        for who in ["alice@example.com", "taken@example.com"] {
            scheme
                .register(
                    email(who),
                    password.clone(),
                    RegistrationData {
                        requires_2fa: false,
                    },
                )
                .await
                .unwrap();
        }
        let login = |who: &str| {
            scheme.login(PasswordCredentials {
                email: Secret::new(who.to_string()),
                password: Secret::new("a-long-password".to_string()),
            })
        };
        let Ok(LoginOutcome::Success(token)) = login("alice@example.com").await else {
            panic!("alice logs in");
        };
        let alice = email("alice@example.com");

        // The signups' verification links first.
        for who in ["alice@example.com", "taken@example.com"] {
            outbox
                .find(who, |m| matches!(m, Mail::VerifyEmail { .. }).then_some(()))
                .await;
        }

        // A taken address: its owner is told, nothing is offered to move.
        let before = outbox.count();
        scheme
            .request_email_change(alice.clone(), email("taken@example.com"))
            .await
            .unwrap();
        outbox
            .find("taken@example.com", |m| {
                matches!(m, Mail::AlreadyRegistered).then_some(())
            })
            .await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(
            outbox.count(),
            before + 1,
            "no confirmation for a taken address"
        );

        // A free address: a token to it, a notice to the old one.
        scheme
            .request_email_change(alice.clone(), email("alice@new.example.com"))
            .await
            .unwrap();
        let confirm = outbox
            .find("alice@new.example.com", |m| match m {
                Mail::ConfirmEmailChange { token } => Some(token.clone()),
                _ => None,
            })
            .await;
        outbox
            .find("alice@example.com", |m| {
                matches!(m, Mail::EmailChangeRequested { new } if new == "alice@new.example.com")
                    .then_some(())
            })
            .await;

        // From someone else's session, the token moves nothing (and is used).
        assert!(
            scheme
                .confirm_email_change(email("taken@example.com"), confirm.clone())
                .await
                .is_err()
        );
        assert!(users.get_user(&alice).await.is_ok());

        // Ask again and confirm from the account itself.
        scheme
            .request_email_change(alice.clone(), email("alice@new.example.com"))
            .await
            .unwrap();
        let confirm = {
            let mut tokens = Vec::new();
            for _ in 0..1000 {
                tokens = outbox
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .filter_map(|(_, m)| match m {
                        Mail::ConfirmEmailChange { token } => Some(token.clone()),
                        _ => None,
                    })
                    .collect();
                if tokens.len() == 2 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            tokens.pop().expect("a second confirmation")
        };
        assert!(validates(&scheme, &token).await);
        let moved = scheme
            .confirm_email_change(alice.clone(), confirm.clone())
            .await
            .unwrap();
        assert_eq!(moved, email("alice@new.example.com"));

        // The old session is over, the old address is free, and the account
        // logs in at the new one, already verified.
        assert!(!validates(&scheme, &token).await);
        assert!(login("alice@example.com").await.is_err());
        assert!(matches!(
            login("alice@new.example.com").await,
            Ok(LoginOutcome::Success(_))
        ));
        assert!(scheme.is_email_verified(&moved).await.unwrap());
        assert!(!scheme.is_email_verified(&alice).await.unwrap());

        // Single use.
        assert!(scheme.confirm_email_change(moved, confirm).await.is_err());
    }
}
