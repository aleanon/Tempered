//! The Axum auth service.
//!
//! `auth_service(scheme, assets)` mounts every route the scheme serves (its
//! [route table](tempered_adapters::endpoints)), at the paths and tiers the
//! table gives. You don't opt routes in here; the scheme's `supports_*` calls
//! decide. The only reasons to call a method on the service are to
//! **override a default path** (e.g. `.login("/signin")`, or
//! `.path(RouteId::Login, "/signin")`) or to attach your own router with
//! [`validated_router`](AuthService::validated_router),
//! [`verified_router`](AuthService::verified_router) or
//! [`validated_elevated_router`](AuthService::validated_elevated_router).
//!
//! The library's routes check their own tier inside the scheme's
//! [`Endpoints::handle`]; this module only mounts them. Your routers get the
//! same checks from [`crate::middleware`].

use std::sync::Arc;

use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    middleware,
    routing::{MethodFilter, MethodRouter, on},
};
use tempered_adapters::endpoints::{EndpointRequest, Endpoints, PathOverrides, RouteId, RouteSpec};
use tempered_core::{
    AuthValidator, AuthenticationScheme, ClassifyError, IdentityClaims, RequiresEmailVerification,
    SupportsElevation,
};
use tokio::net::TcpListener;
use tower_http::services::{ServeDir, ServeFile};
use tracing::info;

use crate::adapters::into_axum_response;

/// Layers a tier check over a router. Stored as a plain `fn` so the generic
/// build can call it without the bounds the check needs (elevation, claims
/// that name a user), which only the method that attaches the router names.
type LayerFn<S> = fn(Router<S>, S) -> Router<S>;

/// Serve `scheme`'s routes, and static files from `assets_dir` for anything
/// else. `assets_dir` must be a directory of public files only: everything
/// in it, dotfiles included, is served.
pub fn auth_service<S>(scheme: S, assets_dir: String) -> AuthService<S>
where
    S: Endpoints + AuthenticationScheme + Clone + Send + Sync + 'static,
    S::Validator: AuthValidator<RequestParts = http::request::Parts>,
    <S::Validator as AuthValidator>::Error: ClassifyError,
{
    AuthService {
        scheme,
        assets_dir,
        overrides: PathOverrides::default(),
        extra_validated: Router::new(),
        extra_verified: None,
        extra_elevated: None,
    }
}

pub struct AuthService<S> {
    scheme: S,
    assets_dir: String,
    overrides: PathOverrides,
    extra_validated: Router<S>,
    extra_verified: Option<(Router<S>, LayerFn<S>)>,
    extra_elevated: Option<(Router<S>, LayerFn<S>)>,
}

/// Generates a path-override builder method for one route.
macro_rules! override_path {
    ($(#[$m:meta])* $name:ident => $id:ident) => {
        $(#[$m])*
        pub fn $name(mut self, path: impl Into<String>) -> Self {
            self.overrides.set(RouteId::$id, path);
            self
        }
    };
}

impl<S> AuthService<S>
where
    S: Endpoints + AuthenticationScheme + Clone + Send + Sync + 'static,
    S::Validator: AuthValidator<RequestParts = http::request::Parts>,
    <S::Validator as AuthValidator>::Error: ClassifyError,
{
    /// Serve `route` at `path` instead of its default. Every route has an
    /// override this way, including ones added after this method; the named
    /// methods below are shorthands.
    pub fn path(mut self, route: RouteId, path: impl Into<String>) -> Self {
        self.overrides.set(route, path);
        self
    }

    // --- path overrides (each defaults to the route's standard path) ---
    override_path!(/// Override the login path (default `/login`).
        login => Login);
    override_path!(/// Override the logout path (default `/logout`).
        logout => Logout);
    override_path!(/// Override the verify-token path (default `/verify-token`).
        verify_token => VerifyToken);
    override_path!(/// Override the signup path (default `/signup`).
        signup => Signup);
    override_path!(/// Override the verify-2fa path (default `/verify-2fa`).
        verify_2fa => Verify2Fa);
    override_path!(/// Override the change-password path (default `/change-password`, or `/elevated/change-password`).
        change_password => ChangePassword);
    override_path!(/// Override the delete-account path (default `/delete-account`, or `/elevated/delete-account`).
        delete_account => DeleteAccount);
    override_path!(/// Override the elevate path (default `/elevate`).
        elevate => Elevate);
    override_path!(/// Override the verify-elevated-token path (default `/elevated/verify-token`).
        verify_elevated_token => VerifyElevatedToken);
    override_path!(/// Override the email-verification path (default `/verify-email`).
        verify_email => VerifyEmail);
    override_path!(/// Override the resend-verification path (default `/verify-email/resend`).
        resend_verification => ResendVerification);

    /// Override the passkey route prefix (default `/passkey`).
    pub fn passkeys(mut self, prefix: impl Into<String>) -> Self {
        self.overrides.set_passkey_prefix(prefix);
        self
    }

    /// Override the password-reset paths (defaults `/password-reset/initiate` and `/complete`).
    pub fn password_reset(
        mut self,
        initiate: impl Into<String>,
        complete: impl Into<String>,
    ) -> Self {
        self.overrides.set(RouteId::PasswordResetInitiate, initiate);
        self.overrides.set(RouteId::PasswordResetComplete, complete);
        self
    }

    /// Override the OAuth start + callback paths (defaults
    /// `/oauth/{provider}/start|callback`). Both must keep `{provider}`.
    pub fn oauth(mut self, start: impl Into<String>, callback: impl Into<String>) -> Self {
        self.overrides.set(RouteId::OAuthStart, start);
        self.overrides.set(RouteId::OAuthCallback, callback);
        self
    }

    /// Protect a user-supplied router with the login check. Handlers read
    /// the token's claims with `Extension<Claims>`.
    pub fn validated_router(mut self, router: impl Into<Router<S>>) -> Self {
        self.extra_validated = self.extra_validated.merge(router.into());
        self
    }

    /// Runs the service on `listener`.
    pub async fn run(self, listener: TcpListener) -> Result<(), std::io::Error> {
        let router = self.into_router();
        info!(
            "listening on {}",
            listener
                .local_addr()
                .expect("Failed to get address from listener")
        );
        axum::serve(listener, router).await
    }

    fn into_router(self) -> Router {
        let scheme = self.scheme;

        // 1. The library's routes, straight from the table. Each checks its
        //    own tier when it runs.
        let mut router = Router::new();
        for spec in scheme.routes(&self.overrides) {
            let path = spec.path.clone();
            router = router.route(&path, mount(spec));
        }

        // 2. The app's routers, behind the same checks. The verified check
        //    reads the claims the login check inserts, so the login layer
        //    goes outermost.
        let mut validated = self.extra_validated;
        if let Some((verified, apply)) = self.extra_verified {
            validated = validated.merge(apply(verified, scheme.clone()));
        }
        let validated = validated.layer(middleware::from_fn_with_state(
            scheme.clone(),
            crate::middleware::validate_token::<S>,
        ));
        router = router.merge(validated);
        if let Some((elevated, apply)) = self.extra_elevated {
            router = router.merge(apply(elevated, scheme.clone()));
        }

        // 3. State + static assets.
        let assets = ServeDir::new(&self.assets_dir)
            .not_found_service(ServeFile::new(format!("{}/index.html", self.assets_dir)));
        router.with_state(scheme).fallback_service(assets)
    }
}

/// Mount one library route: read the request, hand it to the scheme.
fn mount<S>(spec: RouteSpec) -> MethodRouter<S>
where
    S: Endpoints + Clone + Send + Sync + 'static,
{
    let filter = MethodFilter::try_from(spec.method.clone())
        .unwrap_or_else(|_| panic!("route {:?} uses an unsupported method", spec.id));
    let spec = Arc::new(spec);
    // `Bytes` reads the body under axum's body limit (2 MB by default).
    if spec.params().is_empty() {
        on(
            filter,
            move |State(scheme): State<S>, parts: http::request::Parts, body: Bytes| {
                let spec = spec.clone();
                async move {
                    let request = EndpointRequest::new(parts, body, Vec::new());
                    into_axum_response(scheme.handle(&spec, request).await)
                }
            },
        )
    } else {
        on(
            filter,
            move |State(scheme): State<S>,
                  Path(params): Path<Vec<(String, String)>>,
                  parts: http::request::Parts,
                  body: Bytes| {
                let spec = spec.clone();
                async move {
                    let request = EndpointRequest::new(parts, body, params);
                    into_axum_response(scheme.handle(&spec, request).await)
                }
            },
        )
    }
}

impl<S> AuthService<S>
where
    S: Endpoints + AuthenticationScheme + RequiresEmailVerification + Clone + Send + Sync + 'static,
    S::Validator: AuthValidator<RequestParts = http::request::Parts>,
    <S::Validator as AuthValidator>::Error: ClassifyError,
    <S::Validator as AuthValidator>::Claims: IdentityClaims,
{
    /// Protect a user-supplied router with the login check **and** a verified
    /// email address (403 otherwise). Requires the scheme to support email
    /// verification (`supports_email_verification`), since that is what
    /// knows whether an address is verified.
    ///
    /// The tiers nest: public routes, then
    /// [`validated_router`](Self::validated_router) for any logged-in user,
    /// then this, then
    /// [`validated_elevated_router`](Self::validated_elevated_router)
    /// (reached through `/elevate`, itself a verified route). The address is
    /// looked up on every request to these routes.
    pub fn verified_router(mut self, router: impl Into<Router<S>>) -> Self {
        let merged = match self.extra_verified.take() {
            Some((existing, _)) => existing.merge(router.into()),
            None => router.into(),
        };
        self.extra_verified = Some((merged, apply_verified::<S>));
        self
    }
}

impl<S> AuthService<S>
where
    S: Endpoints + SupportsElevation + Clone + Send + Sync + 'static,
    S::Validator: AuthValidator<RequestParts = http::request::Parts>,
    <S::Validator as AuthValidator>::Error: ClassifyError,
    S::ElevatedValidator: AuthValidator<RequestParts = http::request::Parts>,
    <S::ElevatedValidator as AuthValidator>::Error: ClassifyError,
{
    /// Protect a user-supplied router with the **elevated** token check.
    /// Requires the scheme to support elevation.
    pub fn validated_elevated_router(mut self, router: impl Into<Router<S>>) -> Self {
        let merged = match self.extra_elevated.take() {
            Some((existing, _)) => existing.merge(router.into()),
            None => router.into(),
        };
        self.extra_elevated = Some((merged, apply_elevated::<S>));
        self
    }
}

/// The verified check runs inside the login check (applied by the caller,
/// outermost): it reads the claims that one inserted.
fn apply_verified<S>(router: Router<S>, scheme: S) -> Router<S>
where
    S: Endpoints + AuthenticationScheme + Clone + Send + Sync + 'static,
    S::Validator: AuthValidator<RequestParts = http::request::Parts>,
    <S::Validator as AuthValidator>::Claims: IdentityClaims,
{
    router.layer(middleware::from_fn_with_state(
        scheme,
        crate::middleware::require_verified_email::<S>,
    ))
}

fn apply_elevated<S>(router: Router<S>, scheme: S) -> Router<S>
where
    S: SupportsElevation + Clone + Send + Sync + 'static,
    S::ElevatedValidator: AuthValidator<RequestParts = http::request::Parts>,
    <S::ElevatedValidator as AuthValidator>::Error: ClassifyError,
{
    router.layer(middleware::from_fn_with_state(
        scheme,
        crate::middleware::validate_elevated_token::<S>,
    ))
}

impl<S> From<AuthService<S>> for Router
where
    S: Endpoints + AuthenticationScheme + Clone + Send + Sync + 'static,
    S::Validator: AuthValidator<RequestParts = http::request::Parts>,
    <S::Validator as AuthValidator>::Error: ClassifyError,
{
    fn from(service: AuthService<S>) -> Router {
        service.into_router()
    }
}
