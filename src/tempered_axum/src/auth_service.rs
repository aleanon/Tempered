//! The Axum auth service.
//!
//! `auth_service(scheme, assets)` reads the capabilities the scheme declared with
//! its `supports_*` builders and **auto-wires** all the matching routes at the
//! right authz level (see [`crate::wiring`]). You don't opt routes in here — the
//! scheme is the source of truth. The only reason to call a method on the service
//! is to **override a default path** (e.g. `.login("/signin")`) or to attach your
//! own router with [`validated_router`](AuthService::validated_router),
//! [`verified_router`](AuthService::verified_router) or
//! [`validated_elevated_router`](AuthService::validated_elevated_router).

use crate::IntoStatusMessage;
use axum::{Router, middleware};
use tempered_core::{
    AuthValidator, AuthenticationScheme, HttpAuthenticationScheme, HttpElevationScheme,
    RequiresEmailVerification, SupportsElevation,
};
use tokio::net::TcpListener;
use tower_http::services::{ServeDir, ServeFile};
use tracing::info;

use crate::route_config::{Routers, apply_elevated_validation};
use crate::wiring::{AutoWire, PathOverrides};

/// Bounds a scheme must satisfy to be served: it auto-wires, delivers tokens over
/// HTTP, and its validator reads `http::request::Parts`.
pub fn auth_service<S>(scheme: S, assets_dir: String) -> AuthService<S>
where
    S: HttpAuthenticationScheme<LogoutOutput = String> + AutoWire + Send + Sync + Clone + 'static,
    S::AuthError: IntoStatusMessage,
    <S as AuthenticationScheme>::Validator: AuthValidator<RequestParts = http::request::Parts>,
    <<S as AuthenticationScheme>::Validator as AuthValidator>::Error: IntoStatusMessage,
{
    AuthService {
        scheme,
        assets_dir,
        overrides: PathOverrides::default(),
        extra_validated: Router::new(),
        extra_verified: Router::new(),
        extra_elevated: None,
    }
}

pub struct AuthService<S> {
    scheme: S,
    assets_dir: String,
    overrides: PathOverrides,
    extra_validated: Router<S>,
    extra_verified: Router<S>,
    extra_elevated: Option<Router<S>>,
}

/// Generates a path-override builder method that sets one field of [`PathOverrides`].
macro_rules! override_path {
    ($(#[$m:meta])* $name:ident => $field:ident) => {
        $(#[$m])*
        pub fn $name(mut self, path: impl Into<String>) -> Self {
            self.overrides.$field = Some(path.into());
            self
        }
    };
}

impl<S> AuthService<S>
where
    S: HttpAuthenticationScheme<LogoutOutput = String> + AutoWire + Send + Sync + Clone + 'static,
    S::AuthError: IntoStatusMessage,
    <S as AuthenticationScheme>::Validator: AuthValidator<RequestParts = http::request::Parts>,
    <<S as AuthenticationScheme>::Validator as AuthValidator>::Error: IntoStatusMessage,
{
    // --- path overrides (each defaults to the route's standard path) ---
    override_path!(/// Override the login path (default `/login`).
        login => login);
    override_path!(/// Override the logout path (default `/logout`).
        logout => logout);
    override_path!(/// Override the verify-token path (default `/verify-token`).
        verify_token => verify_token);
    override_path!(/// Override the signup path (default `/signup`).
        signup => signup);
    override_path!(/// Override the verify-2fa path (default `/verify-2fa`).
        verify_2fa => verify_2fa);
    override_path!(/// Override the change-password path (default `/change-password`, or `/elevated/change-password`).
        change_password => change_password);
    override_path!(/// Override the delete-account path (default `/delete-account`, or `/elevated/delete-account`).
        delete_account => delete_account);
    override_path!(/// Override the elevate path (default `/elevate`).
        elevate => elevate);
    override_path!(/// Override the verify-elevated-token path (default `/elevated/verify-token`).
        verify_elevated_token => verify_elevated_token);
    override_path!(/// Override the email-verification path (default `/verify-email`).
        verify_email => verify_email);
    override_path!(/// Override the resend-verification path (default `/verify-email/resend`).
        resend_verification => resend_verification);
    override_path!(/// Override the passkey route prefix (default `/passkey`).
        passkeys => passkey_prefix);

    /// Override the password-reset paths (defaults `/password-reset/initiate` and `/complete`).
    pub fn password_reset(
        mut self,
        initiate: impl Into<String>,
        complete: impl Into<String>,
    ) -> Self {
        self.overrides.password_reset_initiate = Some(initiate.into());
        self.overrides.password_reset_complete = Some(complete.into());
        self
    }

    /// Override the OAuth start + callback paths (defaults `/oauth/{provider}/start|callback`).
    pub fn oauth(mut self, start: impl Into<String>, callback: impl Into<String>) -> Self {
        self.overrides.oauth_start = Some(start.into());
        self.overrides.oauth_callback = Some(callback.into());
        self
    }

    /// Protect a user-supplied router with the regular token middleware (login).
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

        // 1. Auto-wire every declared capability into the buckets.
        let mut routers = scheme.auto_wire(Routers::empty(), &self.overrides);

        // 2. Merge any user-supplied routers.
        routers.validated_router = routers.validated_router.merge(self.extra_validated);

        // The verified bucket sits inside the login bucket: the login
        // middleware (applied below, outermost) validates the token, then the
        // verified check reads its claims. Without email verification there
        // is no check and these are plain login routes.
        let verified = routers.verified_router.merge(self.extra_verified);
        let verified = match routers.verified_layer {
            Some(apply) => apply(verified, scheme.clone()),
            None => verified,
        };
        routers.validated_router = routers.validated_router.merge(verified);
        if let Some(extra) = self.extra_elevated {
            routers.elevated_router =
                Some(routers.elevated_router.unwrap_or_default().merge(extra));
        }

        // 3. Apply the login middleware to the validated bucket and merge.
        let validated = routers
            .validated_router
            .layer(middleware::from_fn_with_state(
                scheme.clone(),
                crate::middleware::validate_token::<S>,
            ));
        let router = routers.main_router.merge(validated);

        // 4. Protect + merge the elevated bucket, if any (via the stored applier).
        let router = match (routers.elevated_router, routers.elevated_layer) {
            (Some(elevated), Some(apply)) => router.merge(apply(elevated, scheme.clone())),
            _ => router,
        };

        // 5. State + static assets.
        let assets = ServeDir::new(&self.assets_dir)
            .not_found_service(ServeFile::new(format!("{}/index.html", self.assets_dir)));
        router.with_state(scheme).fallback_service(assets)
    }
}

impl<S> AuthService<S>
where
    S: HttpAuthenticationScheme<LogoutOutput = String>
        + RequiresEmailVerification
        + AutoWire
        + Send
        + Sync
        + Clone
        + 'static,
    S::AuthError: IntoStatusMessage,
    <S as AuthenticationScheme>::Validator: AuthValidator<RequestParts = http::request::Parts>,
    <<S as AuthenticationScheme>::Validator as AuthValidator>::Error: IntoStatusMessage,
{
    /// Protect a user-supplied router with the login middleware **and** a
    /// verified email address (403 otherwise). Requires the scheme to support
    /// email verification (`supports_email_verification`), since that is what
    /// knows whether an address is verified.
    ///
    /// The tiers nest: public routes (login, `/verify-email`), then
    /// [`validated_router`](Self::validated_router) for any logged-in user
    /// (logout, `/verify-email/resend`), then this, then
    /// [`validated_elevated_router`](Self::validated_elevated_router) (reached
    /// through `/elevate`, itself a verified route). The address is looked up
    /// on every request to these routes.
    pub fn verified_router(mut self, router: impl Into<Router<S>>) -> Self {
        self.extra_verified = self.extra_verified.merge(router.into());
        self
    }
}

impl<S> AuthService<S>
where
    S: HttpElevationScheme<LogoutOutput = String> + AutoWire + Send + Sync + Clone + 'static,
    S::AuthError: IntoStatusMessage,
    <S as AuthenticationScheme>::Validator: AuthValidator<RequestParts = http::request::Parts>,
    <<S as AuthenticationScheme>::Validator as AuthValidator>::Error: IntoStatusMessage,
    <S as SupportsElevation>::ElevatedValidator: AuthValidator<RequestParts = http::request::Parts>,
    <<S as SupportsElevation>::ElevatedValidator as AuthValidator>::Error: IntoStatusMessage,
{
    /// Protect a user-supplied router with the **elevated** token middleware.
    /// Requires the scheme to support elevation (so the elevated bucket is
    /// protected). Uses the same applier `apply_elevated_validation` sets up.
    pub fn validated_elevated_router(mut self, router: impl Into<Router<S>>) -> Self {
        // Touch the applier so the intent is explicit; the elevated bucket's
        // middleware is installed at build (the elevation slot always wires it).
        let _ = apply_elevated_validation::<S>;
        self.extra_elevated = Some(match self.extra_elevated.take() {
            Some(existing) => existing.merge(router.into()),
            None => router.into(),
        });
        self
    }
}

impl<S> From<AuthService<S>> for Router
where
    S: HttpAuthenticationScheme<LogoutOutput = String> + AutoWire + Send + Sync + Clone + 'static,
    S::AuthError: IntoStatusMessage,
    <S as AuthenticationScheme>::Validator: AuthValidator<RequestParts = http::request::Parts>,
    <<S as AuthenticationScheme>::Validator as AuthValidator>::Error: IntoStatusMessage,
{
    fn from(service: AuthService<S>) -> Router {
        service.into_router()
    }
}
