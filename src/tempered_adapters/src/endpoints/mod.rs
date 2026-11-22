//! Framework-neutral routes: which routes a scheme serves, and serving them.
//!
//! A web-framework adapter does not decide anything about authentication
//! routes. It asks the scheme for its [`routes`](Endpoints::routes), mounts
//! each [`RouteSpec`] at its method and path, and forwards matching requests
//! to [`handle`](Endpoints::handle). `handle` checks the route's [`Tier`]
//! itself, so an adapter cannot put a route behind the wrong check. See
//! `docs/ROUTE_TABLE_DESIGN.md`.
//!
//! What stays in the adapter: turning its request into an [`EndpointRequest`]
//! (the framework reads the body, so its size limit applies) and the
//! [`EndpointResponse`] back, static files, and the tier checks for the
//! app's own routes, which use the same [`validate_login`] /
//! [`validate_elevated`] / [`Endpoints::check_verified`] functions.

// A rejected request is answered with a response, so functions that can
// reject return `Result<_, EndpointResponse>`. Boxing it would only add an
// allocation on the rejection path (the axum middleware makes the same call).
#![allow(clippy::result_large_err)]

mod credential;
mod request;
#[cfg(test)]
mod table_tests;

use std::collections::HashMap;

use async_trait::async_trait;
use http::{Method, StatusCode, request::Parts};
use tempered_core::{
    AuthValidator, AuthenticationScheme, ClassifyError, Email, ErrorCategory, IdentityClaims,
    SupportsElevation,
};

pub use credential::SlotEndpoints;
pub use request::{EndpointRequest, RequestHead};

/// What [`Endpoints::handle`] answers with: status, headers (cookies,
/// `Location`) and a body. The same type the handlers already build.
pub type EndpointResponse = http::Response<String>;

/// Every route the library can serve.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RouteId {
    Login,
    Logout,
    VerifyToken,
    Signup,
    ChangePassword,
    DeleteAccount,
    Verify2Fa,
    Elevate,
    VerifyElevation2Fa,
    VerifyElevatedToken,
    PasswordResetInitiate,
    PasswordResetComplete,
    VerifyEmail,
    ResendVerification,
    OAuthStart,
    OAuthCallback,
    PasskeyRegisterStart,
    PasskeyRegisterFinish,
    PasskeyLoginStart,
    PasskeyLoginFinish,
}

/// What a request must prove before a route runs. The tiers nest: a
/// verified user is logged in, and the elevated tier is reached through
/// `/elevate`, itself a verified route.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    /// Anyone.
    Public,
    /// A valid login token.
    Login,
    /// A valid login token and a verified address, when the scheme has email
    /// verification. Without it the scheme cannot tell, and this is `Login`.
    Verified,
    /// A valid elevated ("sudo") token.
    Elevated,
}

/// One route: what it is, where it is mounted, and what it requires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteSpec {
    pub id: RouteId,
    pub method: Method,
    /// Path template; parameters are written `{name}` (axum's and actix's
    /// syntax). Use [`RouteSpec::path_with`] for frameworks that differ.
    pub path: String,
    pub tier: Tier,
}

impl RouteSpec {
    /// The path with each `{name}` parameter rendered by `param` (e.g.
    /// `|name| format!(":{name}")` for frameworks that use `:name`).
    pub fn path_with(&self, param: impl Fn(&str) -> String) -> String {
        let mut out = String::with_capacity(self.path.len());
        let mut rest = self.path.as_str();
        while let Some(start) = rest.find('{') {
            out.push_str(&rest[..start]);
            let end = rest[start..]
                .find('}')
                .map(|i| start + i)
                .unwrap_or(rest.len() - 1);
            out.push_str(&param(&rest[start + 1..end]));
            rest = &rest[end + 1..];
        }
        out.push_str(rest);
        out
    }

    /// The `{name}` parameters in the path, in order.
    pub fn params(&self) -> Vec<&str> {
        let mut names = Vec::new();
        let mut rest = self.path.as_str();
        while let Some(start) = rest.find('{') {
            let Some(len) = rest[start..].find('}') else {
                break;
            };
            names.push(&rest[start + 1..start + len]);
            rest = &rest[start + len + 1..];
        }
        names
    }
}

/// Paths that differ from a route's default.
#[derive(Clone, Debug, Default)]
pub struct PathOverrides {
    paths: HashMap<RouteId, String>,
    passkey_prefix: Option<String>,
}

impl PathOverrides {
    /// Serve `id` at `path` instead of its default.
    pub fn set(&mut self, id: RouteId, path: impl Into<String>) {
        self.paths.insert(id, path.into());
    }

    /// The override for `id`, if any.
    pub fn get(&self, id: RouteId) -> Option<&str> {
        self.paths.get(&id).map(String::as_str)
    }

    /// Mount the four passkey routes under `prefix` (default `/passkey`). A
    /// per-route override still wins.
    pub fn set_passkey_prefix(&mut self, prefix: impl Into<String>) {
        self.passkey_prefix = Some(prefix.into());
    }

    pub fn passkey_prefix(&self) -> &str {
        self.passkey_prefix.as_deref().unwrap_or("/passkey")
    }

    /// The override for `id`, or `default`.
    pub(crate) fn path_or(&self, id: RouteId, default: &str) -> String {
        self.get(id).unwrap_or(default).to_string()
    }
}

/// The routes of a scheme, and serving them.
#[async_trait]
pub trait Endpoints: Send + Sync {
    /// The routes this scheme serves, with `overrides` applied.
    ///
    /// # Panics
    ///
    /// If two routes end up with the same method and path, or an override
    /// drops a parameter the route needs (`{provider}` for OAuth). Both are
    /// configuration errors, caught at startup.
    fn routes(&self, overrides: &PathOverrides) -> Vec<RouteSpec>;

    /// Check `spec.tier`, then run the route. Always answers: errors are
    /// classified into a status and a `{"error": ..}` body.
    async fn handle(&self, spec: &RouteSpec, request: EndpointRequest) -> EndpointResponse;

    /// The verified-tier check for an authenticated user: `Ok` if their
    /// address is verified, or if the scheme cannot tell (no email
    /// verification). Adapters call it for the app's own verified routes.
    async fn check_verified(&self, email: &Email) -> Result<(), EndpointResponse>;
}

/// Check `routes` for clashes and missing parameters (see
/// [`Endpoints::routes`]), then return them.
pub(crate) fn checked(routes: Vec<RouteSpec>) -> Vec<RouteSpec> {
    let mut seen: HashMap<(Method, &str), RouteId> = HashMap::new();
    for spec in &routes {
        if let Some(other) = seen.insert((spec.method.clone(), spec.path.as_str()), spec.id) {
            panic!(
                "routes {other:?} and {:?} are both {} {}; override one of their paths",
                spec.id, spec.method, spec.path
            );
        }
        if matches!(spec.id, RouteId::OAuthStart | RouteId::OAuthCallback)
            && !spec.params().contains(&"provider")
        {
            panic!(
                "route {:?} at {:?} needs a {{provider}} path parameter",
                spec.id, spec.path
            );
        }
    }
    routes
}

// ============================================================================
// Responses
// ============================================================================

/// The HTTP status for a classified error.
pub fn status_for(category: ErrorCategory) -> StatusCode {
    match category {
        ErrorCategory::Unauthorized => StatusCode::UNAUTHORIZED,
        ErrorCategory::BadRequest => StatusCode::BAD_REQUEST,
        ErrorCategory::Conflict => StatusCode::CONFLICT,
        ErrorCategory::NotFound => StatusCode::NOT_FOUND,
        ErrorCategory::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
        ErrorCategory::BadGateway => StatusCode::BAD_GATEWAY,
        ErrorCategory::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// `status` with a JSON body.
pub fn json_response(status: StatusCode, body: serde_json::Value) -> EndpointResponse {
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(body.to_string())
        .expect("a status and a static header always build")
}

/// `status` with `{"error": message}`.
pub fn error_response(status: StatusCode, message: &str) -> EndpointResponse {
    json_response(status, serde_json::json!({ "error": message }))
}

/// A classified error as a response.
pub fn classified(error: impl ClassifyError) -> EndpointResponse {
    let (category, message) = error.classify();
    error_response(status_for(category), &message)
}

// ============================================================================
// Tier checks (shared with the adapters' middleware for the app's routes)
// ============================================================================

/// Validate the login token in `parts` and return its claims.
pub async fn validate_login<S>(
    scheme: &S,
    parts: &Parts,
) -> Result<<S::Validator as AuthValidator>::Claims, EndpointResponse>
where
    S: AuthenticationScheme,
    S::Validator: AuthValidator<RequestParts = Parts>,
    <S::Validator as AuthValidator>::Error: ClassifyError,
{
    scheme.validator().validate(parts).await.map_err(classified)
}

/// Validate the elevated token in `parts` and return its claims.
pub async fn validate_elevated<S>(
    scheme: &S,
    parts: &Parts,
) -> Result<<S::ElevatedValidator as AuthValidator>::Claims, EndpointResponse>
where
    S: SupportsElevation,
    S::ElevatedValidator: AuthValidator<RequestParts = Parts>,
    <S::ElevatedValidator as AuthValidator>::Error: ClassifyError,
{
    scheme
        .elevated_validator()
        .validate(parts)
        .await
        .map_err(classified)
}

/// The user a validated token belongs to.
pub fn subject_email<C: IdentityClaims>(claims: &C) -> Result<Email, EndpointResponse> {
    Email::try_from(claims.subject().clone())
        .map_err(|_| error_response(StatusCode::UNAUTHORIZED, "Invalid session"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(path: &str) -> RouteSpec {
        RouteSpec {
            id: RouteId::OAuthStart,
            method: Method::GET,
            path: path.to_string(),
            tier: Tier::Public,
        }
    }

    #[test]
    fn path_parameters_render_per_framework() {
        let s = spec("/oauth/{provider}/start");
        assert_eq!(s.params(), ["provider"]);
        assert_eq!(s.path_with(|p| format!(":{p}")), "/oauth/:provider/start");
        assert_eq!(spec("/login").path_with(|p| format!(":{p}")), "/login");
    }

    #[test]
    #[should_panic(expected = "are both POST /login")]
    fn two_routes_at_one_path_are_refused() {
        let route = |id| RouteSpec {
            id,
            method: Method::POST,
            path: "/login".to_string(),
            tier: Tier::Public,
        };
        checked(vec![route(RouteId::Login), route(RouteId::Signup)]);
    }

    #[test]
    #[should_panic(expected = "needs a {provider} path parameter")]
    fn an_oauth_override_must_keep_the_provider() {
        checked(vec![spec("/oauth/start")]);
    }
}
