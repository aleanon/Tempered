//! The route table and dispatcher for [`CredentialScheme`] (JWT and session
//! schemes) and [`ApiKeyScheme`].
//!
//! The always-on routes (login, logout, verify-token, and the flag-gated
//! signup, password change and account deletion) are served here. Each
//! capability slot contributes its own routes through [`SlotEndpoints`]: a
//! no-op for `()` (capability off), the real routes for the filled slot. A
//! slot lists only routes its own `handle` serves, so the table and the
//! dispatcher cannot drift, and a scheme without a capability has neither
//! its routes nor its code paths.

use async_trait::async_trait;
use http::{Method, StatusCode, request::Parts};
use secrecy::{ExposeSecret, Secret};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tempered_core::{
    AuthValidator, AuthenticationScheme, CeremonyId, ClassifyError, Email,
    HttpAuthenticationScheme, HttpElevationScheme, HttpOAuth2Scheme, IdentityClaims, Password,
    RequiresEmailVerification, SupportsAccountDeletion, SupportsPasskeys, SupportsPasswordChange,
    SupportsPasswordReset, SupportsRegistration, SupportsTotp, SupportsTwoFactor, TwoFaCode,
    constant_time_eq,
};

use super::{
    EndpointRequest, EndpointResponse, Endpoints, PathOverrides, RouteId, RouteSpec, Tier, checked,
    classified, error_response, json_response, status_for, subject_email, validate_elevated,
    validate_login,
};
use crate::authentication::api_key_scheme::ApiKeyScheme;
use crate::authentication::credential_scheme::{
    Authz, CredentialScheme, ElevatedCookieName, Elevation, ElevationRevoke, EmailVerify, OAuth,
    Passkeys, PasswordReset, RouteFlags, TwoFa,
};
use crate::authentication::token_strategy::TokenStrategy;
use crate::authentication::totp::Totp;
use crate::handlers::{self, verify_2fa::Verify2FaError};
use crate::http::HttpResponseBuilder;

/// What one capability slot contributes to the route table. Every method
/// has a no-op default, which is all `()` (capability off) uses.
///
/// Public only because it appears in the bounds of the [`Endpoints`] impl
/// for [`CredentialScheme`]; not meant to be implemented outside this crate.
#[async_trait]
pub trait SlotEndpoints<S: Sync>: Send + Sync {
    /// Append this capability's routes.
    fn routes(&self, _flags: &RouteFlags, _o: &PathOverrides, _out: &mut Vec<RouteSpec>) {}

    /// Serve `id` if it is one of this capability's routes (`who` is the
    /// caller the route's tier admitted), or `None`.
    async fn handle(
        &self,
        _scheme: &S,
        _id: RouteId,
        _req: &EndpointRequest,
        _who: Option<&Email>,
    ) -> Option<EndpointResponse> {
        None
    }

    /// The verified-tier check (email verification slot).
    async fn check_verified(&self, _scheme: &S, _email: &Email) -> Result<(), EndpointResponse> {
        Ok(())
    }

    /// The elevated-tier check (elevation slot); `None` without elevation.
    async fn elevated_identity(
        &self,
        _scheme: &S,
        _parts: &Parts,
    ) -> Option<Result<Email, EndpointResponse>> {
        None
    }

    /// Logout, if this slot changes it (elevation also revokes the elevated
    /// token).
    async fn logout(&self, _scheme: &S, _req: &EndpointRequest) -> Option<EndpointResponse> {
        None
    }
}

impl<S: Sync> SlotEndpoints<S> for () {}

fn route(id: RouteId, method: Method, path: String, tier: Tier) -> RouteSpec {
    RouteSpec {
        id,
        method,
        path,
        tier,
    }
}

/// The account a public request names: its JSON body's `email`, if it parses
/// as an address (normalised like every other lookup). Anything else names
/// none, and only the per-client limit applies.
fn account_named_in(req: &EndpointRequest) -> Option<Email> {
    #[derive(serde::Deserialize)]
    struct Named {
        email: String,
    }
    let named: Named = serde_json::from_slice(&req.body).ok()?;
    Email::try_from(secrecy::Secret::new(named.email)).ok()
}

fn not_logged_in() -> EndpointResponse {
    error_response(StatusCode::UNAUTHORIZED, "Not logged in")
}

fn parse<T: DeserializeOwned>(req: &EndpointRequest) -> Result<T, EndpointResponse> {
    req.json()
}

/// Run `f`, turning `Err(response)` into the answer.
macro_rules! respond {
    ($body:expr) => {{
        let result: Result<EndpointResponse, EndpointResponse> = (async { $body }).await;
        Some(result.unwrap_or_else(|response| response))
    }};
}

fn bad_request(message: impl std::fmt::Display) -> EndpointResponse {
    error_response(StatusCode::BAD_REQUEST, &message.to_string())
}

/// A failed OAuth callback spends the state cookie too. A success clears it
/// in `create_oauth_callback_response`; a failure must as well, or the
/// cookie lingers until it expires and the next attempt starts beside it.
/// The cookie that binds a provider *link* (not a login) to the browser.
/// Separate from the login state cookie, so the callback knows which one it
/// is finishing, and each refuses the other's state.
pub const OAUTH_LINK_STATE_COOKIE: &str = "__Host-oauth_link_state";

/// `response` with the link state cookie expired.
fn with_link_state_cleared(mut response: EndpointResponse) -> EndpointResponse {
    let cookie = crate::cookie_util::expired_cookie(OAUTH_LINK_STATE_COOKIE);
    if let Ok(value) = http::HeaderValue::from_str(&cookie) {
        response
            .headers_mut()
            .append(http::header::SET_COOKIE, value);
    }
    response
}

/// The user's own API keys: list (with the scopes they may ask for), revoke.
async fn api_keys(
    store: &dyn tempered_core::ApiKeyStore,
    id: RouteId,
    req: &EndpointRequest,
    email: Email,
    allowed_scopes: &[String],
) -> Result<EndpointResponse, EndpointResponse> {
    use crate::authentication::api_key_scheme::store_err;
    let internal = |e: tempered_core::ApiKeyStoreError| classified(store_err(e));
    if id == RouteId::ApiKeyList {
        let keys = store.list_for_user(&email).await.map_err(internal)?;
        return Ok(json_response(
            StatusCode::OK,
            json!({ "keys": keys, "allowedScopes": allowed_scopes }),
        ));
    }
    let key_id = req
        .param("id")
        .and_then(tempered_core::ApiKeyId::parse)
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Not found"))?;
    match store.revoke_key(&email, &key_id).await {
        Ok(()) => Ok(json_response(StatusCode::OK, json!({}))),
        Err(tempered_core::ApiKeyStoreError::NotFound) => {
            Err(error_response(StatusCode::NOT_FOUND, "Not found"))
        }
        Err(e) => Err(internal(e)),
    }
}

/// `200 {}` if the thing was the user's, `404` otherwise.
fn found(done: bool) -> Result<EndpointResponse, EndpointResponse> {
    if done {
        Ok(json_response(StatusCode::OK, json!({})))
    } else {
        Err(error_response(StatusCode::NOT_FOUND, "Not found"))
    }
}

fn redirect(location: &str, cookie: &str) -> EndpointResponse {
    http::Response::builder()
        .status(StatusCode::FOUND)
        .header(http::header::LOCATION, location)
        .header(http::header::SET_COOKIE, cookie)
        .body(String::new())
        .expect("a redirect always builds")
}

fn with_state_cleared<S: HttpOAuth2Scheme>(
    scheme: &S,
    mut response: EndpointResponse,
) -> EndpointResponse {
    let cookie = crate::cookie_util::expired_cookie(scheme.oauth_state_cookie_name());
    if let Ok(value) = http::HeaderValue::from_str(&cookie) {
        response
            .headers_mut()
            .append(http::header::SET_COOKIE, value);
    }
    response
}

// ============================================================================
// CredentialScheme: the always-on routes, the tiers, and the slots
// ============================================================================

type LoginClaims<S> = <<S as AuthenticationScheme>::Validator as AuthValidator>::Claims;

#[derive(Deserialize)]
struct SignupRequest<D> {
    email: Secret<String>,
    password: Secret<String>,
    #[serde(flatten)]
    registration_data: D,
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    new_password: Secret<String>,
}

// The private slot traits in the bounds are internal by design.
#[allow(private_bounds)]
#[async_trait]
impl<U, T, F, L, R, M, O, K> Endpoints for CredentialScheme<U, T, F, L, R, M, O, K>
where
    Self: HttpAuthenticationScheme<LogoutOutput = String, Token = T::Token>
        + SupportsRegistration
        + SupportsPasswordChange
        + SupportsAccountDeletion
        + Send
        + Sync,
    <Self as AuthenticationScheme>::AuthError: ClassifyError,
    <Self as SupportsRegistration>::RegistrationError: ClassifyError,
    <Self as SupportsPasswordChange>::PasswordChangeError: ClassifyError,
    <Self as SupportsAccountDeletion>::AccountDeletionError: ClassifyError,
    <Self as AuthenticationScheme>::Validator: AuthValidator<RequestParts = Parts>,
    <<Self as AuthenticationScheme>::Validator as AuthValidator>::Error: ClassifyError,
    LoginClaims<Self>: IdentityClaims,
    T: TokenStrategy,
    F: SlotEndpoints<Self>,
    L: SlotEndpoints<Self> + ElevationRevoke + ElevatedCookieName,
    R: SlotEndpoints<Self>,
    M: SlotEndpoints<Self>,
    O: SlotEndpoints<Self>,
    K: SlotEndpoints<Self>,
    U: tempered_core::UserStore,
{
    fn routes(&self, o: &PathOverrides) -> Vec<RouteSpec> {
        use RouteId::*;
        let flags = self.route_flags();
        let path = |id, default: &str| o.path_or(id, default);
        let mut out = vec![
            route(Login, Method::POST, path(Login, "/login"), Tier::Public),
            route(
                VerifyToken,
                Method::POST,
                path(VerifyToken, "/verify-token"),
                Tier::Login,
            ),
            route(Logout, Method::POST, path(Logout, "/logout"), Tier::Login),
        ];
        if self.api_key_store().is_some() {
            // Issuing or revoking a key is a credential change: elevated
            // when the scheme can elevate, a verified address otherwise.
            let (prefix, tier) = if self.has_elevation() {
                ("/elevated", Tier::Elevated)
            } else {
                ("", Tier::Verified)
            };
            out.push(route(
                ApiKeyList,
                Method::GET,
                path(ApiKeyList, "/api-keys"),
                Tier::Login,
            ));
            out.push(route(
                ApiKeyIssue,
                Method::POST,
                path(ApiKeyIssue, &format!("{prefix}/api-keys")),
                tier,
            ));
            out.push(route(
                ApiKeyRevoke,
                Method::DELETE,
                path(ApiKeyRevoke, &format!("{prefix}/api-keys/{{id}}")),
                tier,
            ));
        }
        if self.token_strategy().lists_sessions() {
            // The user's own sessions: a login is enough (ending one is
            // logging out a device, not a credential change).
            out.push(route(
                ListSessions,
                Method::GET,
                path(ListSessions, "/sessions"),
                Tier::Login,
            ));
            out.push(route(
                EndSession,
                Method::DELETE,
                path(EndSession, "/sessions/{handle}"),
                Tier::Login,
            ));
        }
        if self.token_strategy().refreshes() {
            // Public: the refresh token is the credential.
            out.push(route(
                Refresh,
                Method::POST,
                path(Refresh, "/refresh"),
                Tier::Public,
            ));
        }
        if flags.registration {
            out.push(route(
                Signup,
                Method::POST,
                path(Signup, "/signup"),
                Tier::Public,
            ));
        }
        // Changing a credential needs a verified address. Deleting the
        // account does not: whoever signed up with a mistyped address can
        // still remove it.
        match flags.password_change {
            None => {}
            Some(Authz::Login) => out.push(route(
                ChangePassword,
                Method::POST,
                path(ChangePassword, "/change-password"),
                Tier::Verified,
            )),
            Some(Authz::Elevated) => out.push(route(
                ChangePassword,
                Method::POST,
                path(ChangePassword, "/elevated/change-password"),
                Tier::Elevated,
            )),
        }
        match flags.account_deletion {
            None => {}
            Some(Authz::Login) => out.push(route(
                DeleteAccount,
                Method::DELETE,
                path(DeleteAccount, "/delete-account"),
                Tier::Login,
            )),
            Some(Authz::Elevated) => out.push(route(
                DeleteAccount,
                Method::DELETE,
                path(DeleteAccount, "/elevated/delete-account"),
                Tier::Elevated,
            )),
        }

        let (f, l, r, m, oauth, k) = self.slots();
        f.routes(flags, o, &mut out);
        l.routes(flags, o, &mut out);
        r.routes(flags, o, &mut out);
        m.routes(flags, o, &mut out);
        oauth.routes(flags, o, &mut out);
        k.routes(flags, o, &mut out);
        checked(out)
    }

    async fn handle(&self, spec: &RouteSpec, req: EndpointRequest) -> EndpointResponse {
        // One span per library request: the route and, at the end, the
        // status. No addresses, codes or tokens.
        let span =
            tracing::info_span!("tempered.route", route = ?spec.id, status = tracing::field::Empty);
        let client = (self.auth_event_sink().is_some())
            .then(|| req.parts.extensions.get::<super::ClientAddr>().map(|c| c.0))
            .flatten();
        let (response, account) =
            tracing::Instrument::instrument(self.serve(spec, req), span.clone()).await;
        span.record("status", response.status().as_u16());
        #[cfg(feature = "metrics")]
        metrics::counter!(
            "tempered_requests_total",
            "route" => format!("{:?}", spec.id),
            "status" => response.status().as_str().to_string(),
        )
        .increment(1);
        if let Some(sink) = self.auth_event_sink() {
            sink.record(super::AuthEvent {
                route: spec.id,
                status: response.status().as_u16(),
                account,
                client,
            })
            .await;
        }
        response
    }

    async fn check_verified(&self, email: &Email) -> Result<(), EndpointResponse> {
        self.slots().3.check_verified(self, email).await
    }
}

#[allow(private_bounds)]
impl<U, T, F, L, R, M, O, K> CredentialScheme<U, T, F, L, R, M, O, K>
where
    Self: HttpAuthenticationScheme<LogoutOutput = String, Token = T::Token>
        + SupportsRegistration
        + SupportsPasswordChange
        + SupportsAccountDeletion
        + Send
        + Sync,
    <Self as AuthenticationScheme>::AuthError: ClassifyError,
    <Self as SupportsRegistration>::RegistrationError: ClassifyError,
    <Self as SupportsPasswordChange>::PasswordChangeError: ClassifyError,
    <Self as SupportsAccountDeletion>::AccountDeletionError: ClassifyError,
    <Self as AuthenticationScheme>::Validator: AuthValidator<RequestParts = Parts>,
    <<Self as AuthenticationScheme>::Validator as AuthValidator>::Error: ClassifyError,
    LoginClaims<Self>: IdentityClaims,
    T: TokenStrategy,
    F: SlotEndpoints<Self>,
    L: SlotEndpoints<Self> + ElevationRevoke + ElevatedCookieName,
    R: SlotEndpoints<Self>,
    M: SlotEndpoints<Self>,
    O: SlotEndpoints<Self>,
    K: SlotEndpoints<Self>,
    U: tempered_core::UserStore,
{
    /// The route, behind the span and counter `handle` adds.
    /// The route, and the account it concerned (the admitted user, or for
    /// a public route the address its body names), for the audit event.
    async fn serve(
        &self,
        spec: &RouteSpec,
        req: EndpointRequest,
    ) -> (EndpointResponse, Option<Email>) {
        // Before anything else: a page on another site does not get to log
        // the visitor in, sign them up or change their account. Reads (the
        // OAuth start and callback, which a provider redirect makes
        // cross-site by design) are left alone.
        if !matches!(spec.method, Method::GET | Method::HEAD) && super::is_cross_site(&req.parts) {
            return (super::cross_site_refused(), None);
        }
        let who = match self.admit(spec.tier, &req.parts).await {
            Ok(who) => who,
            Err(response) => return (response, account_named_in(&req)),
        };
        let account = who.clone().or_else(|| account_named_in(&req));
        (
            self.dispatch(spec, &req, who.as_ref(), account.as_ref())
                .await,
            account,
        )
    }

    async fn dispatch(
        &self,
        spec: &RouteSpec,
        req: &EndpointRequest,
        who: Option<&Email>,
        account: Option<&Email>,
    ) -> EndpointResponse {
        // Count the attempt before doing anything for it. The account is the
        // admitted user, or for public routes the address the body names.
        if let Some(limiter) = self.rate_limiter()
            && let Err(response) = limiter.check(spec.id, &req.parts, account).await
        {
            return response;
        }
        if let Some(response) = self.handle_core(spec.id, req, who).await {
            return response;
        }
        let (f, l, r, m, o, k) = self.slots();
        if let Some(response) = f.handle(self, spec.id, req, who).await {
            return response;
        }
        if let Some(response) = l.handle(self, spec.id, req, who).await {
            return response;
        }
        if let Some(response) = r.handle(self, spec.id, req, who).await {
            return response;
        }
        if let Some(response) = m.handle(self, spec.id, req, who).await {
            return response;
        }
        if let Some(response) = o.handle(self, spec.id, req, who).await {
            return response;
        }
        if let Some(response) = k.handle(self, spec.id, req, who).await {
            return response;
        }
        error_response(StatusCode::NOT_FOUND, "Not found")
    }
}

#[allow(private_bounds)]
impl<U, T, F, L, R, M, O, K> CredentialScheme<U, T, F, L, R, M, O, K>
where
    Self: HttpAuthenticationScheme<LogoutOutput = String, Token = T::Token>
        + SupportsRegistration
        + SupportsPasswordChange
        + SupportsAccountDeletion
        + Send
        + Sync,
    <Self as AuthenticationScheme>::AuthError: ClassifyError,
    <Self as SupportsRegistration>::RegistrationError: ClassifyError,
    <Self as SupportsPasswordChange>::PasswordChangeError: ClassifyError,
    <Self as SupportsAccountDeletion>::AccountDeletionError: ClassifyError,
    <Self as AuthenticationScheme>::Validator: AuthValidator<RequestParts = Parts>,
    <<Self as AuthenticationScheme>::Validator as AuthValidator>::Error: ClassifyError,
    LoginClaims<Self>: IdentityClaims,
    T: TokenStrategy,
    L: SlotEndpoints<Self> + ElevationRevoke + ElevatedCookieName,
    M: SlotEndpoints<Self>,
    U: tempered_core::UserStore,
    F: Send + Sync,
    R: Send + Sync,
    O: Send + Sync,
    K: Send + Sync,
{
    /// Check `tier` and return who passed it (`None` for public routes).
    async fn admit(&self, tier: Tier, parts: &Parts) -> Result<Option<Email>, EndpointResponse> {
        match tier {
            Tier::Public => Ok(None),
            Tier::Login | Tier::Verified => {
                let claims = validate_login(self, parts).await?;
                let email = subject_email(&claims)?;
                if tier == Tier::Verified {
                    self.slots().3.check_verified(self, &email).await?;
                }
                Ok(Some(email))
            }
            Tier::Elevated => match self.slots().1.elevated_identity(self, parts).await {
                Some(result) => result.map(Some),
                // Unreachable in a table this scheme built: elevated routes
                // exist only with elevation.
                None => Err(not_logged_in()),
            },
        }
    }

    async fn handle_core(
        &self,
        id: RouteId,
        req: &EndpointRequest,
        who: Option<&Email>,
    ) -> Option<EndpointResponse> {
        match id {
            RouteId::ApiKeyIssue => {
                self.api_key_store()?;
                respond!({
                    #[derive(Deserialize)]
                    #[serde(rename_all = "camelCase")]
                    struct Issue {
                        #[serde(default)]
                        scopes: Vec<String>,
                        expires_in_days: Option<u64>,
                    }
                    let email = who.cloned().ok_or_else(not_logged_in)?;
                    let request: Issue = parse(req)?;
                    if request.expires_in_days == Some(0) {
                        return Err(bad_request("expiresInDays must be at least 1"));
                    }
                    let expires_at = request.expires_in_days.map(|days| {
                        crate::authentication::api_key_scheme::unix_now() + days.min(3650) * 86_400
                    });
                    let (key_id, key) = self
                        .issue_user_api_key(email, request.scopes, expires_at)
                        .await
                        .map_err(classified)?;
                    // The only time the key is shown.
                    Ok(json_response(
                        StatusCode::CREATED,
                        json!({ "id": key_id.to_string(), "apiKey": key, "expiresAt": expires_at }),
                    ))
                })
            }
            RouteId::ApiKeyList | RouteId::ApiKeyRevoke => {
                let store = self.api_key_store()?.clone();
                let allowed = self.allowed_api_key_scopes().to_vec();
                respond!({
                    let email = who.cloned().ok_or_else(not_logged_in)?;
                    api_keys(&*store, id, req, email, &allowed).await
                })
            }
            RouteId::ListSessions => respond!({
                let email = who.cloned().ok_or_else(not_logged_in)?;
                let tokens = self.token_strategy();
                let current = tokens.extract(&req.head());
                let sessions = tokens
                    .sessions(&email, current.as_ref())
                    .await
                    .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Not found"))?
                    .map_err(classified)?;
                Ok(json_response(
                    StatusCode::OK,
                    json!({ "sessions": sessions }),
                ))
            }),
            RouteId::EndSession => respond!({
                let email = who.cloned().ok_or_else(not_logged_in)?;
                let handle = req.param("handle").unwrap_or_default();
                let ended = self
                    .end_device_session(&email, handle)
                    .await
                    .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Not found"))?
                    .map_err(classified)?;
                if ended {
                    Ok(json_response(StatusCode::OK, json!({})))
                } else {
                    Err(error_response(StatusCode::NOT_FOUND, "No such session"))
                }
            }),
            RouteId::Refresh => respond!({
                #[derive(Deserialize)]
                struct RefreshBody {
                    #[serde(rename = "refreshToken")]
                    refresh_token: String,
                }
                let tokens = self.token_strategy();
                // The cookie, or for bearer clients the body.
                let presented = tokens
                    .refresh_cookie_name()
                    .and_then(|name| crate::cookie_util::cookie_value(&req.parts, name))
                    .filter(|v| !v.is_empty())
                    .or_else(|| {
                        serde_json::from_slice::<RefreshBody>(&req.body)
                            .ok()
                            .map(|b| b.refresh_token)
                    })
                    .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "Log in again"))?;
                let token = match tokens.refresh(&presented).await {
                    Some(result) => result.map_err(classified)?,
                    None => return Err(error_response(StatusCode::NOT_FOUND, "Not found")),
                };
                self.create_login_response(
                    HttpResponseBuilder::new(),
                    tempered_core::LoginOutcome::Success(token),
                )
                .map_err(|e| {
                    tracing::error!(error = %e, "response builder failed (scheme bug)");
                    error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                })
            }),
            RouteId::Login => respond!({
                let credentials = parse(req)?;
                handlers::handle_login(self, credentials, HttpResponseBuilder::new())
                    .await
                    .map_err(classified)
            }),
            RouteId::VerifyToken => respond!({
                handlers::handle_verify_token(HttpResponseBuilder::new())
                    .await
                    .map_err(|e| error_response(StatusCode::UNAUTHORIZED, &e))
            }),
            RouteId::Logout => {
                if let Some(response) = self.slots().1.logout(self, req).await {
                    return Some(response);
                }
                respond!({
                    handlers::handle_logout(self, &req.head(), HttpResponseBuilder::new())
                        .await
                        .map_err(|e| error_response(StatusCode::UNAUTHORIZED, &e))
                })
            }
            RouteId::Signup => respond!({
                let request: SignupRequest<<Self as SupportsRegistration>::RegistrationData> =
                    parse(req)?;
                let email = Email::try_from(request.email).map_err(bad_request)?;
                let password = Password::try_from(request.password).map_err(bad_request)?;
                let data = handlers::signup::SignupData {
                    email,
                    password,
                    registration_data: request.registration_data,
                };
                handlers::handle_signup(self, data, HttpResponseBuilder::new())
                    .await
                    .map_err(classified)
            }),
            RouteId::ChangePassword => respond!({
                let email = who.ok_or_else(not_logged_in)?.clone();
                let request: ChangePasswordRequest = parse(req)?;
                let new_password = Password::try_from(request.new_password).map_err(bad_request)?;
                self.change_password(email, new_password)
                    .await
                    .map_err(classified)?;
                Ok(json_response(
                    StatusCode::OK,
                    json!({ "status": "success", "message": "Password changed successfully" }),
                ))
            }),
            RouteId::DeleteAccount => respond!({
                let email = who.ok_or_else(not_logged_in)?.clone();
                self.delete_account(email).await.map_err(classified)?;
                Ok(http::Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(String::new())
                    .expect("a status always builds"))
            }),
            _ => None,
        }
    }
}

// ============================================================================
// Slots
// ============================================================================

// ---- 2FA -------------------------------------------------------------------

#[derive(Deserialize)]
struct Verify2FaRequest {
    email: Secret<String>,
    #[serde(rename = "loginAttemptId")]
    login_attempt_id: String,
    #[serde(rename = "2FACode")]
    two_factor_code: String,
}

#[async_trait]
impl<S, St, E, P> SlotEndpoints<S> for TwoFa<St, E, P>
where
    S: HttpAuthenticationScheme + SupportsTwoFactor + tempered_core::SupportsEmailLogin + Sync,
    S::TwoFactorError: ClassifyError,
    S::EmailLoginError: ClassifyError,
    St: Send + Sync,
    E: Send + Sync,
    P: TotpEndpoints<S>,
{
    fn routes(&self, flags: &RouteFlags, o: &PathOverrides, out: &mut Vec<RouteSpec>) {
        out.push(route(
            RouteId::Verify2Fa,
            Method::POST,
            o.path_or(RouteId::Verify2Fa, "/verify-2fa"),
            Tier::Public,
        ));
        if self.email_login_enabled() {
            for (id, path) in [
                (RouteId::EmailLoginStart, "/email-login/start"),
                (RouteId::EmailLoginVerify, "/email-login/verify"),
            ] {
                out.push(route(id, Method::POST, o.path_or(id, path), Tier::Public));
            }
        }
        self.totp().routes(flags, o, out);
    }

    async fn handle(
        &self,
        scheme: &S,
        id: RouteId,
        req: &EndpointRequest,
        who: Option<&Email>,
    ) -> Option<EndpointResponse> {
        match id {
            RouteId::Verify2Fa => {}
            RouteId::EmailLoginStart | RouteId::EmailLoginVerify if self.email_login_enabled() => {
                return email_login(scheme, id, req).await;
            }
            _ => return self.totp().handle(scheme, id, req, who).await,
        }
        respond!({
            let request: Verify2FaRequest = parse(req)?;
            let data = handlers::verify_2fa::Verify2FaData {
                email: request.email.expose_secret().clone(),
                login_attempt_id: request.login_attempt_id,
                two_factor_code: request.two_factor_code,
            };
            handlers::handle_verify_2fa(scheme, data, HttpResponseBuilder::new())
                .await
                .map_err(|e| match e {
                    Verify2FaError::InvalidEmail(e) => bad_request(e),
                    Verify2FaError::InvalidAttemptId(e) | Verify2FaError::InvalidCode(e) => {
                        bad_request(e)
                    }
                    Verify2FaError::VerificationFailed(e) => classified(e),
                    Verify2FaError::ResponseBuild(e) => {
                        tracing::error!(error = %e, "response builder failed (scheme bug)");
                        error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                    }
                })
        })
    }
}

/// The passwordless email login routes of the 2FA slot.
async fn email_login<S>(scheme: &S, id: RouteId, req: &EndpointRequest) -> Option<EndpointResponse>
where
    S: HttpAuthenticationScheme + tempered_core::SupportsEmailLogin + Sync,
    S::EmailLoginError: ClassifyError,
{
    #[derive(Deserialize)]
    struct Start {
        email: Secret<String>,
    }
    #[derive(Deserialize)]
    struct Verify {
        email: Secret<String>,
        #[serde(rename = "loginAttemptId")]
        login_attempt_id: String,
        code: String,
    }
    respond!({
        if id == RouteId::EmailLoginStart {
            let request: Start = parse(req)?;
            let email = Email::try_from(request.email).map_err(bad_request)?;
            let attempt = scheme.start_email_login(email).await.map_err(classified)?;
            // The same answer whether or not the address has an account.
            return Ok(json_response(
                StatusCode::OK,
                json!({ "loginAttemptId": attempt.to_string() }),
            ));
        }
        let request: Verify = parse(req)?;
        let email = Email::try_from(request.email).map_err(bad_request)?;
        let attempt =
            tempered_core::TwoFaAttemptId::parse(&request.login_attempt_id).map_err(bad_request)?;
        let code = TwoFaCode::parse(request.code).map_err(bad_request)?;
        let outcome = scheme
            .finish_email_login(email, attempt, code)
            .await
            .map_err(classified)?;
        scheme
            .create_login_response(HttpResponseBuilder::new(), outcome)
            .map_err(|e| {
                tracing::error!(error = %e, "response builder failed (scheme bug)");
                error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })
    })
}

// ---- TOTP (part of the 2FA slot) --------------------------------------------

/// The TOTP routes of the 2FA slot: none for `()`, four for [`Totp`].
#[async_trait]
pub trait TotpEndpoints<S: Sync>: Send + Sync {
    fn routes(&self, _flags: &RouteFlags, _o: &PathOverrides, _out: &mut Vec<RouteSpec>) {}

    async fn handle(
        &self,
        _scheme: &S,
        _id: RouteId,
        _req: &EndpointRequest,
        _who: Option<&Email>,
    ) -> Option<EndpointResponse> {
        None
    }
}

impl<S: Sync> TotpEndpoints<S> for () {}

#[derive(Deserialize)]
struct TotpCodeRequest {
    code: String,
}

#[async_trait]
impl<S, TS> TotpEndpoints<S> for Totp<TS>
where
    S: SupportsTotp + Sync,
    S::TotpError: ClassifyError,
    TS: Send + Sync,
{
    fn routes(&self, _flags: &RouteFlags, o: &PathOverrides, out: &mut Vec<RouteSpec>) {
        // Adding or removing a second factor is a credential change: elevated.
        for (id, path) in [
            (RouteId::TotpStart, "/elevated/totp/start"),
            (RouteId::TotpConfirm, "/elevated/totp/confirm"),
            (RouteId::TotpDisable, "/elevated/totp/disable"),
            (RouteId::TotpRecoveryCodes, "/elevated/totp/recovery-codes"),
        ] {
            out.push(route(id, Method::POST, o.path_or(id, path), Tier::Elevated));
        }
    }

    async fn handle(
        &self,
        scheme: &S,
        id: RouteId,
        req: &EndpointRequest,
        who: Option<&Email>,
    ) -> Option<EndpointResponse> {
        if !matches!(
            id,
            RouteId::TotpStart
                | RouteId::TotpConfirm
                | RouteId::TotpDisable
                | RouteId::TotpRecoveryCodes
        ) {
            return None;
        }
        respond!({
            let email = who.cloned().ok_or_else(not_logged_in)?;
            match id {
                RouteId::TotpStart => {
                    let enrollment = scheme.start_totp(email).await.map_err(classified)?;
                    Ok(json_response(
                        StatusCode::OK,
                        json!({
                            "secret": enrollment.secret.expose_secret(),
                            "otpauthUri": enrollment.otpauth_uri.expose_secret(),
                        }),
                    ))
                }
                RouteId::TotpConfirm => {
                    let request: TotpCodeRequest = parse(req)?;
                    let code = TwoFaCode::parse(request.code).map_err(bad_request)?;
                    let codes = scheme.confirm_totp(email, code).await.map_err(classified)?;
                    Ok(json_response(
                        StatusCode::OK,
                        json!({ "recoveryCodes": codes }),
                    ))
                }
                RouteId::TotpDisable => {
                    scheme.disable_totp(email).await.map_err(classified)?;
                    Ok(json_response(StatusCode::OK, json!({})))
                }
                _ => {
                    let codes = scheme
                        .regenerate_recovery_codes(email)
                        .await
                        .map_err(classified)?;
                    Ok(json_response(
                        StatusCode::OK,
                        json!({ "recoveryCodes": codes }),
                    ))
                }
            }
        })
    }
}

// ---- Elevation -------------------------------------------------------------

/// Like `/verify-2fa`'s body, without the email: the session names the user.
#[derive(Deserialize)]
struct VerifyElevation2FaRequest {
    #[serde(rename = "loginAttemptId")]
    login_attempt_id: String,
    #[serde(rename = "2FACode")]
    two_factor_code: String,
}

#[derive(Deserialize)]
struct ElevateRequest {
    email: Secret<String>,
    password: Secret<String>,
}

#[async_trait]
impl<S, TE> SlotEndpoints<S> for Elevation<TE>
where
    S: HttpElevationScheme + Sync,
    S::ElevationError: ClassifyError,
    S::ElevatedValidator: AuthValidator<RequestParts = Parts>,
    <S::ElevatedValidator as AuthValidator>::Error: ClassifyError,
    <S::ElevatedValidator as AuthValidator>::Claims: IdentityClaims,
    TE: Send + Sync,
{
    fn routes(&self, _flags: &RouteFlags, o: &PathOverrides, out: &mut Vec<RouteSpec>) {
        // `/elevate` needs a verified address, like every credential change;
        // everything elevated is reached through it.
        out.push(route(
            RouteId::Elevate,
            Method::POST,
            o.path_or(RouteId::Elevate, "/elevate"),
            Tier::Verified,
        ));
        // The second step for an account with 2FA. Same tier as `/elevate`;
        // the user is the session's, never the body's.
        out.push(route(
            RouteId::VerifyElevation2Fa,
            Method::POST,
            o.path_or(RouteId::VerifyElevation2Fa, "/elevate/verify-2fa"),
            Tier::Verified,
        ));
        out.push(route(
            RouteId::VerifyElevatedToken,
            Method::POST,
            o.path_or(RouteId::VerifyElevatedToken, "/elevated/verify-token"),
            Tier::Elevated,
        ));
    }

    async fn handle(
        &self,
        scheme: &S,
        id: RouteId,
        req: &EndpointRequest,
        who: Option<&Email>,
    ) -> Option<EndpointResponse> {
        match id {
            RouteId::Elevate => respond!({
                let who = who.ok_or_else(not_logged_in)?;
                let request: ElevateRequest = parse(req)?;
                let email = Email::try_from(request.email).map_err(bad_request)?;
                let password = Password::try_from(request.password).map_err(bad_request)?;
                // Elevation is bound to the session: the body's credentials
                // must be the logged-in user's. The body is attacker-chosen
                // and the session subject is not, so compare in constant time.
                if !constant_time_eq(who.as_ref().expose_secret(), email.as_ref().expose_secret()) {
                    return Err(error_response(
                        StatusCode::FORBIDDEN,
                        "Elevation must target the logged-in user",
                    ));
                }
                handlers::handle_elevate(scheme, email, password, HttpResponseBuilder::new())
                    .await
                    .map_err(|(category, message)| error_response(status_for(category), &message))
            }),
            RouteId::VerifyElevation2Fa => respond!({
                let email = who.ok_or_else(not_logged_in)?.clone();
                let request: VerifyElevation2FaRequest = parse(req)?;
                handlers::handle_verify_elevation_2fa(
                    scheme,
                    email,
                    &request.login_attempt_id,
                    &request.two_factor_code,
                    HttpResponseBuilder::new(),
                )
                .await
                .map_err(|(category, message)| error_response(status_for(category), &message))
            }),
            RouteId::VerifyElevatedToken => respond!({
                handlers::handle_verify_elevated_token(HttpResponseBuilder::new())
                    .await
                    .map_err(|e| error_response(StatusCode::UNAUTHORIZED, &e))
            }),
            _ => None,
        }
    }

    async fn elevated_identity(
        &self,
        scheme: &S,
        parts: &Parts,
    ) -> Option<Result<Email, EndpointResponse>> {
        Some(match validate_elevated(scheme, parts).await {
            Ok(claims) => subject_email(&claims),
            Err(response) => Err(response),
        })
    }

    async fn logout(&self, scheme: &S, req: &EndpointRequest) -> Option<EndpointResponse> {
        respond!({
            handlers::handle_logout_with_elevation(scheme, &req.head(), HttpResponseBuilder::new())
                .await
                .map_err(|e| error_response(StatusCode::UNAUTHORIZED, &e))
        })
    }
}

// ---- Password reset --------------------------------------------------------

#[derive(Deserialize)]
struct InitiateResetRequest {
    email: Secret<String>,
}

#[derive(Deserialize)]
struct CompleteResetRequest {
    reset_token: String,
    new_password: Secret<String>,
}

#[async_trait]
impl<S, P, E> SlotEndpoints<S> for PasswordReset<P, E>
where
    S: SupportsPasswordReset + Sync,
    S::PasswordResetError: ClassifyError,
    P: Send + Sync,
    E: Send + Sync,
{
    fn routes(&self, _flags: &RouteFlags, o: &PathOverrides, out: &mut Vec<RouteSpec>) {
        out.push(route(
            RouteId::PasswordResetInitiate,
            Method::POST,
            o.path_or(RouteId::PasswordResetInitiate, "/password-reset/initiate"),
            Tier::Public,
        ));
        out.push(route(
            RouteId::PasswordResetComplete,
            Method::POST,
            o.path_or(RouteId::PasswordResetComplete, "/password-reset/complete"),
            Tier::Public,
        ));
    }

    async fn handle(
        &self,
        scheme: &S,
        id: RouteId,
        req: &EndpointRequest,
        _who: Option<&Email>,
    ) -> Option<EndpointResponse> {
        match id {
            RouteId::PasswordResetInitiate => respond!({
                let request: InitiateResetRequest = parse(req)?;
                // The same answer whether or not the address is registered.
                if let Ok(email) = Email::try_from(request.email) {
                    let _ = scheme.initiate_password_reset(email).await;
                }
                Ok(json_response(
                    StatusCode::OK,
                    json!({
                        "status": "success",
                        "message": "If that email address is registered, you will receive a password reset link"
                    }),
                ))
            }),
            RouteId::PasswordResetComplete => respond!({
                let request: CompleteResetRequest = parse(req)?;
                let new_password = Password::try_from(request.new_password).map_err(bad_request)?;
                scheme
                    .complete_password_reset(request.reset_token, new_password)
                    .await
                    .map_err(classified)?;
                Ok(json_response(
                    StatusCode::OK,
                    json!({ "status": "success", "message": "Password reset successfully" }),
                ))
            }),
            _ => None,
        }
    }
}

// ---- Email verification ----------------------------------------------------

#[derive(Deserialize)]
struct VerifyEmailRequest {
    token: String,
}

#[async_trait]
impl<S, V, E> SlotEndpoints<S> for EmailVerify<V, E>
where
    S: RequiresEmailVerification
        + tempered_core::SupportsEmailChange
        + HttpAuthenticationScheme
        + Sync,
    S::EmailVerificationError: ClassifyError,
    S::EmailChangeError: ClassifyError,
    V: Send + Sync,
    E: Send + Sync,
{
    fn routes(&self, flags: &RouteFlags, o: &PathOverrides, out: &mut Vec<RouteSpec>) {
        if self.email_change_enabled() {
            // Asking to move the account is a credential change: elevated
            // when the scheme can elevate. Confirming needs the token (the
            // new inbox) and the account's own login.
            let (path, tier) = if flags.has_elevation {
                ("/elevated/email/change", Tier::Elevated)
            } else {
                ("/email/change", Tier::Verified)
            };
            out.push(route(
                RouteId::EmailChangeRequest,
                Method::POST,
                o.path_or(RouteId::EmailChangeRequest, path),
                tier,
            ));
            out.push(route(
                RouteId::EmailChangeConfirm,
                Method::POST,
                o.path_or(RouteId::EmailChangeConfirm, "/email/change/confirm"),
                Tier::Login,
            ));
        }
        // Verifying needs the token (the inbox) and a login (the account):
        // either alone could prove an account someone else created with the
        // address. Login tier, not verified, like asking for another link.
        out.push(route(
            RouteId::VerifyEmail,
            Method::POST,
            o.path_or(RouteId::VerifyEmail, "/verify-email"),
            Tier::Login,
        ));
        out.push(route(
            RouteId::ResendVerification,
            Method::POST,
            o.path_or(RouteId::ResendVerification, "/verify-email/resend"),
            Tier::Login,
        ));
    }

    async fn handle(
        &self,
        scheme: &S,
        id: RouteId,
        req: &EndpointRequest,
        who: Option<&Email>,
    ) -> Option<EndpointResponse> {
        match id {
            RouteId::EmailChangeRequest => respond!({
                #[derive(Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Request {
                    new_email: Secret<String>,
                }
                let email = who.ok_or_else(not_logged_in)?.clone();
                let request: Request = parse(req)?;
                let new = Email::try_from(request.new_email).map_err(bad_request)?;
                scheme
                    .request_email_change(email, new)
                    .await
                    .map_err(classified)?;
                // The same answer whether or not the address is taken.
                Ok(json_response(
                    StatusCode::ACCEPTED,
                    json!({ "message": "Check the new address to confirm the change" }),
                ))
            }),
            RouteId::EmailChangeConfirm => respond!({
                #[derive(Deserialize)]
                struct Request {
                    token: String,
                }
                let email = who.ok_or_else(not_logged_in)?.clone();
                let request: Request = parse(req)?;
                scheme
                    .confirm_email_change(email, request.token)
                    .await
                    .map_err(classified)?;
                // Every session ended with the change: clear this one's
                // cookies too, and the user logs in with the new address.
                scheme
                    .create_logout_response(HttpResponseBuilder::new(), None)
                    .map_err(|e| {
                        tracing::error!(error = %e, "response builder failed (scheme bug)");
                        error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                    })
            }),
            RouteId::VerifyEmail => respond!({
                let email = who.ok_or_else(not_logged_in)?;
                let request: VerifyEmailRequest = parse(req)?;
                handlers::handle_verify_email(
                    scheme,
                    email,
                    request.token,
                    HttpResponseBuilder::new(),
                )
                .await
                .map_err(classified)
            }),
            RouteId::ResendVerification => respond!({
                let email = who.ok_or_else(not_logged_in)?.clone();
                scheme
                    .initiate_email_verification(email)
                    .await
                    .map_err(classified)?;
                Ok(json_response(
                    StatusCode::OK,
                    json!({ "status": "success" }),
                ))
            }),
            _ => None,
        }
    }

    async fn check_verified(&self, scheme: &S, email: &Email) -> Result<(), EndpointResponse> {
        match scheme.is_email_verified(email).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(error_response(
                StatusCode::FORBIDDEN,
                "Email address not verified",
            )),
            Err(e) => Err(classified(e)),
        }
    }
}

// ---- OAuth -----------------------------------------------------------------

#[async_trait]
impl<S, ST, ID, HC> SlotEndpoints<S> for OAuth<ST, ID, HC>
where
    S: HttpOAuth2Scheme + Sync,
    S::OAuth2Error: ClassifyError,
    ST: Send + Sync,
    ID: Send + Sync,
    HC: Send + Sync,
{
    fn routes(&self, flags: &RouteFlags, o: &PathOverrides, out: &mut Vec<RouteSpec>) {
        // GET: the browser is redirected through both.
        out.push(route(
            RouteId::OAuthStart,
            Method::GET,
            o.path_or(RouteId::OAuthStart, "/oauth/{provider}/start"),
            Tier::Public,
        ));
        out.push(route(
            RouteId::OAuthCallback,
            Method::GET,
            o.path_or(RouteId::OAuthCallback, "/oauth/{provider}/callback"),
            Tier::Public,
        ));
        // Self-service. Linking adds a way in, so it needs a verified
        // address (or an elevated token, with step-up), like passkey
        // enrolment; listing needs a login. The link starts with a POST, so
        // another site cannot start it in a visitor's browser (after logging
        // that browser in to the attacker's provider account).
        let (link_path, link_tier) = match flags.oauth_linking {
            Authz::Login => ("/oauth/{provider}/link", Tier::Verified),
            Authz::Elevated => ("/elevated/oauth/{provider}/link", Tier::Elevated),
        };
        out.push(route(
            RouteId::OAuthLinkStart,
            Method::POST,
            o.path_or(RouteId::OAuthLinkStart, link_path),
            link_tier,
        ));
        out.push(route(
            RouteId::OAuthLinks,
            Method::GET,
            o.path_or(RouteId::OAuthLinks, "/oauth/links"),
            Tier::Login,
        ));
        out.push(route(
            RouteId::OAuthUnlink,
            Method::DELETE,
            o.path_or(RouteId::OAuthUnlink, "/oauth/links/{provider}"),
            Tier::Verified,
        ));
    }

    async fn handle(
        &self,
        scheme: &S,
        id: RouteId,
        req: &EndpointRequest,
        who: Option<&Email>,
    ) -> Option<EndpointResponse> {
        let provider = || {
            req.param("provider")
                .ok_or_else(|| bad_request("Missing provider"))
        };
        match id {
            RouteId::OAuthStart => respond!({
                handlers::handle_oauth_start(scheme, provider()?, HttpResponseBuilder::new())
                    .await
                    .map_err(classified)
            }),
            RouteId::OAuthLinkStart => respond!({
                let email = who.cloned().ok_or_else(not_logged_in)?;
                let authorization = scheme
                    .begin_oauth_link(provider()?, email)
                    .await
                    .map_err(classified)?;
                let cookie = format!(
                    "{OAUTH_LINK_STATE_COOKIE}={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600",
                    authorization.state
                );
                Ok(redirect(&authorization.authorize_url, &cookie))
            }),
            RouteId::OAuthLinks => respond!({
                let email = who.cloned().ok_or_else(not_logged_in)?;
                let providers = scheme.oauth_links(&email).await.map_err(classified)?;
                Ok(json_response(
                    StatusCode::OK,
                    json!({ "providers": providers }),
                ))
            }),
            RouteId::OAuthUnlink => respond!({
                let email = who.cloned().ok_or_else(not_logged_in)?;
                if scheme
                    .unlink_oauth(&email, provider()?)
                    .await
                    .map_err(classified)?
                {
                    Ok(json_response(StatusCode::OK, json!({})))
                } else {
                    Err(error_response(StatusCode::NOT_FOUND, "Not linked"))
                }
            }),
            RouteId::OAuthCallback => respond!({
                // The provider sends the user back with `error=` when they
                // cancel or it refuses (RFC 6749 §4.1.2.1). Not a malformed
                // request: the login just did not happen. The value comes
                // from the URL, so anyone can set it; it goes to the log
                // (escaped), not back to the client.
                if let Some(error) = req.query("error") {
                    tracing::info!(error = ?error, "OAuth provider did not complete the login");
                    return Err(with_state_cleared(
                        scheme,
                        error_response(
                            StatusCode::UNAUTHORIZED,
                            "The login with the provider was not completed",
                        ),
                    ));
                }
                let (Some(code), Some(state)) = (req.query("code"), req.query("state")) else {
                    return Err(with_state_cleared(
                        scheme,
                        bad_request("Missing code or state"),
                    ));
                };
                // A link, if the browser holds a link state: it finishes as a
                // link only, and logs nobody in.
                let head = req.head();
                if let Some(link_state) =
                    tempered_core::AuthRequest::cookie(&head, OAUTH_LINK_STATE_COOKIE)
                {
                    let cleared = crate::cookie_util::expired_cookie(OAUTH_LINK_STATE_COOKIE);
                    return scheme
                        .complete_oauth_link(provider()?, &code, &state, link_state)
                        .await
                        .map(|_| redirect(scheme.oauth_link_redirect(), &cleared))
                        .map_err(|e| with_link_state_cleared(classified(e)));
                }
                // The browser-bound state lives in the cookie the start leg set.
                let cookie_state =
                    tempered_core::AuthRequest::cookie(&head, scheme.oauth_state_cookie_name())
                        .unwrap_or("");
                handlers::handle_oauth_callback(
                    scheme,
                    provider()?,
                    &code,
                    &state,
                    cookie_state,
                    HttpResponseBuilder::new(),
                )
                .await
                .map_err(|e| with_state_cleared(scheme, classified(e)))
            }),
            _ => None,
        }
    }
}

// ---- Passkeys --------------------------------------------------------------

#[derive(Deserialize)]
struct PasskeyLoginStartRequest {
    /// Omit for a usernameless (discoverable-credential) ceremony.
    #[serde(default)]
    email: Option<Secret<String>>,
}

#[derive(Deserialize)]
struct PasskeyFinishRequest {
    ceremony_id: String,
    response: Value,
}

#[async_trait]
impl<S, CS, ChS, V> SlotEndpoints<S> for Passkeys<CS, ChS, V>
where
    S: SupportsPasskeys + HttpAuthenticationScheme + Sync,
    S::PasskeyError: ClassifyError,
    CS: Send + Sync,
    ChS: Send + Sync,
    V: Send + Sync,
{
    fn routes(&self, flags: &RouteFlags, o: &PathOverrides, out: &mut Vec<RouteSpec>) {
        let prefix = o.passkey_prefix();
        // Enrolling a passkey grants login as that user, so it always needs
        // an authenticated caller with a verified address, or an elevated
        // token if the scheme asked for step-up. Never public.
        let (enrol_prefix, enrol_tier) = match flags.passkey_enrollment {
            Authz::Login => (prefix.to_string(), Tier::Verified),
            Authz::Elevated => (format!("/elevated{prefix}"), Tier::Elevated),
        };
        for (id, default, tier) in [
            (
                RouteId::PasskeyRegisterStart,
                format!("{enrol_prefix}/register/start"),
                enrol_tier,
            ),
            (
                RouteId::PasskeyRegisterFinish,
                format!("{enrol_prefix}/register/finish"),
                enrol_tier,
            ),
            // Logging in with a passkey is, by definition, unauthenticated.
            (
                RouteId::PasskeyLoginStart,
                format!("{prefix}/login/start"),
                Tier::Public,
            ),
            (
                RouteId::PasskeyLoginFinish,
                format!("{prefix}/login/finish"),
                Tier::Public,
            ),
        ] {
            out.push(route(id, Method::POST, o.path_or(id, &default), tier));
        }
        // The user's own passkeys: listing needs a login; renaming or
        // removing one is a credential change, at the enrolment tier.
        for (id, method, default, tier) in [
            (
                RouteId::PasskeyList,
                Method::GET,
                format!("{prefix}/credentials"),
                Tier::Login,
            ),
            (
                RouteId::PasskeyRename,
                Method::PATCH,
                format!("{enrol_prefix}/credentials/{{id}}"),
                enrol_tier,
            ),
            (
                RouteId::PasskeyDelete,
                Method::DELETE,
                format!("{enrol_prefix}/credentials/{{id}}"),
                enrol_tier,
            ),
        ] {
            out.push(route(id, method, o.path_or(id, &default), tier));
        }
    }

    async fn handle(
        &self,
        scheme: &S,
        id: RouteId,
        req: &EndpointRequest,
        who: Option<&Email>,
    ) -> Option<EndpointResponse> {
        match id {
            RouteId::PasskeyRegisterStart => respond!({
                let email = who.ok_or_else(not_logged_in)?.clone();
                handlers::handle_passkey_register_start(scheme, email, HttpResponseBuilder::new())
                    .await
                    .map_err(classified)
            }),
            RouteId::PasskeyRegisterFinish => respond!({
                let email = who.ok_or_else(not_logged_in)?.clone();
                let request: PasskeyFinishRequest = parse(req)?;
                handlers::handle_passkey_register_finish(
                    scheme,
                    email,
                    CeremonyId(request.ceremony_id),
                    request.response,
                    HttpResponseBuilder::new(),
                )
                .await
                .map_err(classified)
            }),
            RouteId::PasskeyLoginStart => respond!({
                let request: PasskeyLoginStartRequest = parse(req)?;
                let email = request
                    .email
                    .map(Email::try_from)
                    .transpose()
                    .map_err(bad_request)?;
                handlers::handle_passkey_login_start(scheme, email, HttpResponseBuilder::new())
                    .await
                    .map_err(classified)
            }),
            RouteId::PasskeyLoginFinish => respond!({
                let request: PasskeyFinishRequest = parse(req)?;
                handlers::handle_passkey_login_finish(
                    scheme,
                    CeremonyId(request.ceremony_id),
                    request.response,
                    HttpResponseBuilder::new(),
                )
                .await
                .map_err(classified)
            }),
            RouteId::PasskeyList => respond!({
                let email = who.ok_or_else(not_logged_in)?;
                let passkeys = scheme.passkeys(email).await.map_err(classified)?;
                Ok(json_response(
                    StatusCode::OK,
                    json!({ "passkeys": passkeys }),
                ))
            }),
            RouteId::PasskeyRename => respond!({
                #[derive(Deserialize)]
                struct Rename {
                    name: Option<String>,
                }
                let email = who.ok_or_else(not_logged_in)?;
                let request: Rename = parse(req)?;
                let name = request
                    .name
                    .map(|n| n.trim().chars().take(64).collect::<String>())
                    .filter(|n| !n.is_empty());
                let id =
                    tempered_core::CredentialId(req.param("id").unwrap_or_default().to_string());
                found(
                    scheme
                        .rename_passkey(email, &id, name)
                        .await
                        .map_err(classified)?,
                )
            }),
            RouteId::PasskeyDelete => respond!({
                let email = who.ok_or_else(not_logged_in)?;
                let id =
                    tempered_core::CredentialId(req.param("id").unwrap_or_default().to_string());
                found(
                    scheme
                        .delete_passkey(email, &id)
                        .await
                        .map_err(classified)?,
                )
            }),
            _ => None,
        }
    }
}

// ============================================================================
// ApiKeyScheme: no library routes
// ============================================================================

/// API-key schemes have no credential routes to serve. Key issuance needs an
/// owner and scopes the app decides, so it stays an app route.
#[async_trait]
impl<St, I> Endpoints for ApiKeyScheme<St, I>
where
    St: Send + Sync,
    I: Send + Sync,
{
    fn routes(&self, _overrides: &PathOverrides) -> Vec<RouteSpec> {
        Vec::new()
    }

    async fn handle(&self, _spec: &RouteSpec, _request: EndpointRequest) -> EndpointResponse {
        error_response(StatusCode::NOT_FOUND, "Not found")
    }

    async fn check_verified(&self, _email: &Email) -> Result<(), EndpointResponse> {
        Ok(())
    }
}
