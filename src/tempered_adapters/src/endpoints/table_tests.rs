//! The route table: what each capability mounts, where, and at which tier.
//!
//! These pin what `tempered_axum`'s wiring mounted before the table existed,
//! and the tier rules that must hold whatever the scheme enables.

use http::Method;
use secrecy::Secret;
use tempered_core::{OAuthHttpClient, OAuthHttpError, OAuthProviderConfig, OAuthUserInfo};

use super::{Endpoints, PathOverrides, RouteId, RouteSpec, Tier};
use crate::auth_validation::local_jwt_validator::JwtAuthConfig;
use crate::authentication::jwt_scheme::JwtScheme;
use crate::email::MockEmailClient;
use crate::oauth::OAuthFlow;
use crate::passkey::PasskeyFlow;
use crate::passkey::flow::test_support::MockVerifier;
use crate::persistence::{
    HashMapChallengeStore, HashMapEmailVerificationTokenStore, HashMapOAuthIdentityStore,
    HashMapOAuthStateStore, HashMapPasskeyCredentialStore, HashMapPasswordResetTokenStore,
    HashMapTokenEpochStore, HashMapTotpStore, HashMapTwoFaCodeStore, HashMapUserStore,
    HashSetBannedTokenStore,
};

/// Never called: the table is built without any request.
#[derive(Clone)]
struct NoOAuthClient;

#[async_trait::async_trait]
impl OAuthHttpClient for NoOAuthClient {
    async fn fetch_json(&self, _: &str) -> Result<serde_json::Value, OAuthHttpError> {
        unreachable!()
    }

    async fn exchange_code(
        &self,
        _: &OAuthProviderConfig,
        _: &str,
        _: &str,
    ) -> Result<tempered_core::TokenResponse, OAuthHttpError> {
        unreachable!()
    }
    async fn fetch_user_info(
        &self,
        _: &OAuthProviderConfig,
        _: &str,
    ) -> Result<OAuthUserInfo, OAuthHttpError> {
        unreachable!()
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

fn minimal() -> impl Endpoints {
    JwtScheme::new(
        HashMapUserStore::new(),
        config("jwt", "a-test-secret-that-is-long-enough"),
        HashSetBannedTokenStore::new(),
        HashMapTokenEpochStore::new(),
    )
}

/// Every capability. `elevated` puts password change, account deletion and
/// passkey enrolment behind the elevated token.
fn everything(elevated: bool) -> impl Endpoints {
    let oauth = OAuthFlow::new(
        HashMapOAuthStateStore::new(),
        HashMapOAuthIdentityStore::new(),
        NoOAuthClient,
    );
    let passkeys = PasskeyFlow::new(
        HashMapPasskeyCredentialStore::new(),
        HashMapChallengeStore::new(),
        MockVerifier,
    );
    JwtScheme::new(
        HashMapUserStore::new(),
        config("jwt", "a-test-secret-that-is-long-enough"),
        HashSetBannedTokenStore::new(),
        HashMapTokenEpochStore::new(),
    )
    .supports_registration()
    .supports_password_change()
    .supports_account_deletion()
    .supports_2fa(HashMapTwoFaCodeStore::new(), MockEmailClient::new())
    .supports_password_reset(
        HashMapPasswordResetTokenStore::new(),
        MockEmailClient::new(),
    )
    .supports_email_verification(
        HashMapEmailVerificationTokenStore::new(),
        MockEmailClient::new(),
    )
    .supports_oauth(oauth)
    .supports_passkeys(passkeys)
    .supports_elevation(
        HashSetBannedTokenStore::new(),
        config("elevated_jwt", "an-elevated-test-secret-long-enough"),
        move |e| {
            if elevated {
                e.supports_password_change()
                    .supports_account_deletion()
                    .supports_passkey_enrollment()
            } else {
                e
            }
        },
    )
    .supports_totp(HashMapTotpStore::new(), "Test")
}

fn table(
    scheme: &impl Endpoints,
    overrides: &PathOverrides,
) -> Vec<(RouteId, Method, String, Tier)> {
    let mut rows: Vec<_> = scheme
        .routes(overrides)
        .into_iter()
        .map(
            |RouteSpec {
                 id,
                 method,
                 path,
                 tier,
             }| (id, method, path, tier),
        )
        .collect();
    rows.sort_by_key(|row| row.0);
    rows
}

fn row(id: RouteId, method: Method, path: &str, tier: Tier) -> (RouteId, Method, String, Tier) {
    (id, method, path.to_string(), tier)
}

#[test]
fn a_scheme_with_every_capability_serves_the_default_table() {
    use RouteId::*;
    use Tier::*;
    let mut expected = vec![
        row(RouteId::Login, Method::POST, "/login", Public),
        row(Logout, Method::POST, "/logout", Tier::Login),
        row(VerifyToken, Method::POST, "/verify-token", Tier::Login),
        row(Signup, Method::POST, "/signup", Public),
        row(ChangePassword, Method::POST, "/change-password", Verified),
        row(
            DeleteAccount,
            Method::DELETE,
            "/delete-account",
            Tier::Login,
        ),
        row(Verify2Fa, Method::POST, "/verify-2fa", Public),
        row(Elevate, Method::POST, "/elevate", Verified),
        row(
            VerifyElevation2Fa,
            Method::POST,
            "/elevate/verify-2fa",
            Verified,
        ),
        row(
            VerifyElevatedToken,
            Method::POST,
            "/elevated/verify-token",
            Elevated,
        ),
        row(
            PasswordResetInitiate,
            Method::POST,
            "/password-reset/initiate",
            Public,
        ),
        row(
            PasswordResetComplete,
            Method::POST,
            "/password-reset/complete",
            Public,
        ),
        row(VerifyEmail, Method::POST, "/verify-email", Tier::Login),
        row(
            ResendVerification,
            Method::POST,
            "/verify-email/resend",
            Tier::Login,
        ),
        row(OAuthStart, Method::GET, "/oauth/{provider}/start", Public),
        row(
            OAuthCallback,
            Method::GET,
            "/oauth/{provider}/callback",
            Public,
        ),
        row(
            PasskeyRegisterStart,
            Method::POST,
            "/passkey/register/start",
            Verified,
        ),
        row(
            PasskeyRegisterFinish,
            Method::POST,
            "/passkey/register/finish",
            Verified,
        ),
        row(
            PasskeyLoginStart,
            Method::POST,
            "/passkey/login/start",
            Public,
        ),
        row(
            PasskeyLoginFinish,
            Method::POST,
            "/passkey/login/finish",
            Public,
        ),
        row(TotpStart, Method::POST, "/elevated/totp/start", Elevated),
        row(
            TotpConfirm,
            Method::POST,
            "/elevated/totp/confirm",
            Elevated,
        ),
        row(
            TotpDisable,
            Method::POST,
            "/elevated/totp/disable",
            Elevated,
        ),
        row(
            TotpRecoveryCodes,
            Method::POST,
            "/elevated/totp/recovery-codes",
            Elevated,
        ),
    ];
    expected.sort_by_key(|row| row.0);
    assert_eq!(
        table(&everything(false), &PathOverrides::default()),
        expected
    );
}

#[test]
fn step_up_moves_credential_changes_behind_the_elevated_token() {
    let rows = table(&everything(true), &PathOverrides::default());
    let find = |id| rows.iter().find(|r| r.0 == id).unwrap().clone();
    assert_eq!(
        find(RouteId::ChangePassword),
        row(
            RouteId::ChangePassword,
            Method::POST,
            "/elevated/change-password",
            Tier::Elevated
        )
    );
    assert_eq!(
        find(RouteId::DeleteAccount),
        row(
            RouteId::DeleteAccount,
            Method::DELETE,
            "/elevated/delete-account",
            Tier::Elevated
        )
    );
    assert_eq!(
        find(RouteId::PasskeyRegisterStart),
        row(
            RouteId::PasskeyRegisterStart,
            Method::POST,
            "/elevated/passkey/register/start",
            Tier::Elevated
        )
    );
}

#[test]
fn a_scheme_lists_only_the_capabilities_it_has() {
    let ids: Vec<_> = table(&minimal(), &PathOverrides::default())
        .into_iter()
        .map(|r| r.0)
        .collect();
    assert_eq!(ids, [RouteId::Login, RouteId::Logout, RouteId::VerifyToken]);
}

#[test]
fn overrides_move_routes_and_keep_their_tier() {
    let mut o = PathOverrides::default();
    o.set(RouteId::Login, "/signin");
    o.set(RouteId::OAuthStart, "/auth/{provider}");
    o.set_passkey_prefix("/webauthn");
    o.set(RouteId::PasskeyLoginFinish, "/webauthn/done");
    let rows = table(&everything(false), &o);
    let find = |id| rows.iter().find(|r| r.0 == id).unwrap().clone();
    assert_eq!(find(RouteId::Login).2, "/signin");
    assert_eq!(find(RouteId::OAuthStart).2, "/auth/{provider}");
    assert_eq!(
        find(RouteId::PasskeyRegisterStart).2,
        "/webauthn/register/start"
    );
    assert_eq!(find(RouteId::PasskeyRegisterStart).3, Tier::Verified);
    assert_eq!(find(RouteId::PasskeyLoginFinish).2, "/webauthn/done");
}

#[test]
#[should_panic(expected = "are both POST /signup")]
fn an_override_onto_another_route_is_refused() {
    let mut o = PathOverrides::default();
    o.set(RouteId::Login, "/signup");
    everything(false).routes(&o);
}

#[test]
fn tier_rules_hold_for_every_scheme_built_here() {
    for routes in [
        minimal().routes(&PathOverrides::default()),
        everything(false).routes(&PathOverrides::default()),
        everything(true).routes(&PathOverrides::default()),
    ] {
        for spec in &routes {
            use RouteId::*;
            match spec.id {
                // Changing or adding a credential: never below a verified
                // address (the elevated tier is reached through /elevate,
                // itself a verified route).
                ChangePassword
                | PasskeyRegisterStart
                | PasskeyRegisterFinish
                | Elevate
                | VerifyElevation2Fa => {
                    assert!(spec.tier >= Tier::Verified, "{spec:?}")
                }
                // Needs the account's login as well as the inbox.
                VerifyEmail | ResendVerification | Logout | VerifyToken => {
                    assert_eq!(spec.tier, Tier::Login, "{spec:?}")
                }
                DeleteAccount => assert!(spec.tier >= Tier::Login, "{spec:?}"),
                VerifyElevatedToken => assert_eq!(spec.tier, Tier::Elevated, "{spec:?}"),
                // Adding or removing a second factor: a fresh re-authentication.
                TotpStart | TotpConfirm | TotpDisable | TotpRecoveryCodes => {
                    assert_eq!(spec.tier, Tier::Elevated, "{spec:?}")
                }
                // Logging in, signing up and recovering are public by nature.
                Login
                | Signup
                | Verify2Fa
                | PasswordResetInitiate
                | PasswordResetComplete
                | OAuthStart
                | OAuthCallback
                | PasskeyLoginStart
                | PasskeyLoginFinish
                | Refresh => {
                    assert_eq!(spec.tier, Tier::Public, "{spec:?}")
                }
            }
        }
    }
}

/// Run the OAuth callback with `query`, carrying a state cookie.
async fn oauth_callback(query: &str) -> super::EndpointResponse {
    let scheme = everything(false);
    let spec = scheme
        .routes(&PathOverrides::default())
        .into_iter()
        .find(|spec| spec.id == RouteId::OAuthCallback)
        .unwrap();
    let (parts, ()) = http::Request::builder()
        .uri(format!("/oauth/google/callback?{query}"))
        .header(http::header::COOKIE, "__Host-oauth_state=s1")
        .body(())
        .unwrap()
        .into_parts();
    let params = vec![("provider".to_string(), "google".to_string())];
    scheme
        .handle(
            &spec,
            super::EndpointRequest::new(parts, bytes::Bytes::new(), params),
        )
        .await
}

fn clears_the_state_cookie(response: &super::EndpointResponse) -> bool {
    response
        .headers()
        .get_all(http::header::SET_COOKIE)
        .iter()
        .any(|c| {
            let c = c.to_str().unwrap();
            c.starts_with("__Host-oauth_state=;") && c.contains("Max-Age=0")
        })
}

/// A user who cancels at the provider comes back with `error=`. That is a
/// login that did not happen, not a malformed request, and the state cookie
/// is spent either way. The provider is never called (`NoOAuthClient`).
#[tokio::test]
async fn a_refused_oauth_login_answers_401_and_clears_the_state_cookie() {
    let response = oauth_callback("error=access_denied&state=s1").await;
    assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    assert!(clears_the_state_cookie(&response));
    assert!(
        !response.body().contains("access_denied"),
        "the URL's value is not echoed"
    );
}

#[tokio::test]
async fn every_failed_oauth_callback_clears_the_state_cookie() {
    // Malformed: no code.
    let response = oauth_callback("state=s1").await;
    assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    assert!(clears_the_state_cookie(&response));
    // A state the server never issued.
    let response = oauth_callback("code=c&state=s1").await;
    assert!(response.status().is_client_error());
    assert!(clears_the_state_cookie(&response));
}

/// A page on another site cannot post to the library's routes, logged in
/// or not: refused before the body is read or the tier is checked.
#[tokio::test]
async fn a_cross_site_post_is_refused_before_anything_else() {
    let scheme = everything(false);
    let routes = scheme.routes(&PathOverrides::default());
    let login = routes.iter().find(|s| s.id == RouteId::Login).unwrap();
    let post = |site: &str| {
        let (parts, ()) = http::Request::builder()
            .method(Method::POST)
            .uri("/login")
            .header(http::header::CONTENT_TYPE, "application/json")
            .header("sec-fetch-site", site)
            .body(())
            .unwrap()
            .into_parts();
        let body = bytes::Bytes::from(r#"{"email":"a@example.com","password":"long-enough-pw"}"#);
        super::EndpointRequest::new(parts, body, Vec::new())
    };

    let refused = scheme.handle(login, post("cross-site")).await;
    assert_eq!(refused.status(), http::StatusCode::FORBIDDEN);
    // Same origin reaches the route (no such user here: 401).
    let allowed = scheme.handle(login, post("same-origin")).await;
    assert_eq!(allowed.status(), http::StatusCode::UNAUTHORIZED);
}
