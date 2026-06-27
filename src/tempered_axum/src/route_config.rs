use axum::{Router, routing::post};
use tempered_core::{
    AuthValidator, HttpAuthenticationScheme, HttpElevationScheme, IntoStatusMessage,
    RequiresEmailVerification, SupportsElevation, SupportsPasswordReset, SupportsRegistration,
    SupportsTwoFactor,
};

pub struct Routers<Scheme> {
    pub main_router: Router<Scheme>,
    pub validated_router: Router<Scheme>,
    pub elevated_router: Option<Router<Scheme>>,
    /// Applies the elevated-token middleware to [`Self::elevated_router`] at
    /// build time. Stored as a plain `fn` so the base build (which lacks the
    /// `HttpElevationScheme` bound) can call it; the bound is only required to
    /// *take* the pointer, which the elevation builder methods do. See
    /// [`apply_elevated_validation`].
    pub elevated_layer: Option<fn(Router<Scheme>, Scheme) -> Router<Scheme>>,
    /// Registers the logout route. When elevation is configured this is swapped
    /// for the elevation-aware variant (which also revokes the elevated token),
    /// again via a `fn` pointer so the base `logout_route` can install it without
    /// the `HttpElevationScheme` bound. `None` → plain logout. See
    /// [`register_logout_with_elevation`].
    pub logout_register: Option<fn(Router<Scheme>, &str) -> Router<Scheme>>,
}

/// Layer the elevated-token validation middleware over `router`.
///
/// Used as a `fn` pointer stored in [`Routers::elevated_layer`]: the elevation
/// builder methods (which carry the `HttpElevationScheme` bound) hand this to the
/// base build, which can then protect the elevated bucket without naming the
/// bound itself.
pub fn apply_elevated_validation<S>(router: Router<S>, scheme: S) -> Router<S>
where
    S: HttpElevationScheme + SupportsElevation + Clone + Send + Sync + 'static,
    S::ElevatedValidator: AuthValidator<RequestParts = http::request::Parts>,
    <S::ElevatedValidator as AuthValidator>::Error: IntoStatusMessage,
{
    router.layer(axum::middleware::from_fn_with_state(
        scheme,
        crate::middleware::validate_elevated_token::<S>,
    ))
}

/// Register the elevation-aware logout route (revokes the elevated token too).
///
/// Stored as a `fn` pointer in [`Routers::logout_register`] by the elevation
/// builder methods so the base `logout_route` installs the right handler.
pub fn register_logout_with_elevation<S>(validated: Router<S>, logout_path: &str) -> Router<S>
where
    S: HttpElevationScheme + SupportsElevation + Clone + Send + Sync + 'static,
{
    validated.route(
        logout_path,
        post(crate::routes::logout_with_elevation::<S>),
    )
}

pub trait RouteConfig: Sized {
    type Scheme;

    fn get_routers(&mut self) -> Routers<Self::Scheme>;
    fn set_routers(&mut self, routers: Routers<Self::Scheme>);

    // Build method - consumes self and returns final Router
    fn build(self, assets_dir: String, scheme: Self::Scheme) -> Router;

    // Required routes (always present) - paths passed as parameters
    fn login_route(self, login_path: &str, verify_token_path: &str) -> Self;
    fn logout_route(self, logout_path: &str) -> Self;

    // Optional routes (default no-op implementations) - paths passed as parameters
    fn with_signup_route(self, _signup_path: Option<&str>) -> Self {
        self // Default: no-op
    }
    fn with_2fa_route(self, _verify_2fa_path: Option<&str>) -> Self {
        self // Default: no-op
    }
    fn with_password_reset_route(
        self,
        _initiate_path: Option<&str>,
        _complete_path: Option<&str>,
    ) -> Self {
        self // Default: no-op
    }

    fn with_email_verification_route(self, _verify_path: Option<&str>) -> Self {
        self // Default: no-op
    }
}

// ============================================================================
// WithSignupRoute
// ============================================================================

pub fn with_signup_route<R>(instance: R) -> impl RouteConfig<Scheme = R::Scheme>
where
    R: RouteConfig,
    R::Scheme: SupportsRegistration,
    <R::Scheme as SupportsRegistration>::RegistrationError: IntoStatusMessage,
{
    struct WithSignupRoute<R: RouteConfig> {
        instance: R,
    }

    impl<R> RouteConfig for WithSignupRoute<R>
    where
        R: RouteConfig,
        R::Scheme: SupportsRegistration,
        <R::Scheme as SupportsRegistration>::RegistrationError: IntoStatusMessage,
    {
        type Scheme = R::Scheme;

        fn get_routers(&mut self) -> Routers<Self::Scheme> {
            self.instance.get_routers()
        }

        fn set_routers(&mut self, routers: Routers<Self::Scheme>) {
            self.instance.set_routers(routers)
        }

        fn build(self, assets_dir: String, scheme: Self::Scheme) -> Router {
            self.instance.build(assets_dir, scheme)
        }

        fn login_route(mut self, login_path: &str, verify_token_path: &str) -> Self {
            self.instance = self.instance.login_route(login_path, verify_token_path);
            self
        }

        fn logout_route(mut self, logout_path: &str) -> Self {
            self.instance = self.instance.logout_route(logout_path);
            self
        }

        fn with_signup_route(mut self, signup_path: Option<&str>) -> Self {
            if let Some(path) = signup_path {
                let mut routers = self.get_routers();
                routers.main_router = routers
                    .main_router
                    .route(path, post(crate::routes::signup::<Self::Scheme>));
                self.set_routers(routers);
            }
            self
        }

        fn with_2fa_route(mut self, verify_2fa_path: Option<&str>) -> Self {
            self.instance = self.instance.with_2fa_route(verify_2fa_path);
            self
        }

        fn with_password_reset_route(
            mut self,
            initiate_path: Option<&str>,
            complete_path: Option<&str>,
        ) -> Self {
            self.instance = self
                .instance
                .with_password_reset_route(initiate_path, complete_path);
            self
        }

        fn with_email_verification_route(mut self, verify_path: Option<&str>) -> Self {
            self.instance = self.instance.with_email_verification_route(verify_path);
            self
        }
    }

    WithSignupRoute { instance }
}

// ============================================================================
// With2FaRoute
// ============================================================================

pub fn with_2fa_route<R>(instance: R) -> impl RouteConfig<Scheme = R::Scheme>
where
    R: RouteConfig,
    R::Scheme: HttpAuthenticationScheme + SupportsTwoFactor,
    <R::Scheme as SupportsTwoFactor>::TwoFactorError: IntoStatusMessage,
{
    struct With2FaRoute<R: RouteConfig> {
        instance: R,
    }

    impl<R> RouteConfig for With2FaRoute<R>
    where
        R: RouteConfig,
        R::Scheme: HttpAuthenticationScheme + SupportsTwoFactor,
        <R::Scheme as SupportsTwoFactor>::TwoFactorError: IntoStatusMessage,
    {
        type Scheme = R::Scheme;

        fn get_routers(&mut self) -> Routers<Self::Scheme> {
            self.instance.get_routers()
        }

        fn set_routers(&mut self, routers: Routers<Self::Scheme>) {
            self.instance.set_routers(routers)
        }

        fn build(self, assets_dir: String, scheme: Self::Scheme) -> Router {
            self.instance.build(assets_dir, scheme)
        }

        fn login_route(mut self, login_path: &str, verify_token_path: &str) -> Self {
            self.instance = self.instance.login_route(login_path, verify_token_path);
            self
        }

        fn logout_route(mut self, logout_path: &str) -> Self {
            self.instance = self.instance.logout_route(logout_path);
            self
        }

        fn with_signup_route(mut self, signup_path: Option<&str>) -> Self {
            self.instance = self.instance.with_signup_route(signup_path);
            self
        }

        fn with_2fa_route(mut self, verify_2fa_path: Option<&str>) -> Self {
            if let Some(path) = verify_2fa_path {
                let mut routers = self.get_routers();
                routers.main_router = routers
                    .main_router
                    .route(path, post(crate::routes::verify_2fa::<Self::Scheme>));
                self.set_routers(routers);
            }
            self
        }

        fn with_password_reset_route(
            mut self,
            initiate_path: Option<&str>,
            complete_path: Option<&str>,
        ) -> Self {
            self.instance = self
                .instance
                .with_password_reset_route(initiate_path, complete_path);
            self
        }

        fn with_email_verification_route(mut self, verify_path: Option<&str>) -> Self {
            self.instance = self.instance.with_email_verification_route(verify_path);
            self
        }
    }

    With2FaRoute { instance }
}

// ============================================================================
// WithPasswordResetRoute
// ============================================================================

pub fn with_password_reset_route<R>(instance: R) -> impl RouteConfig<Scheme = R::Scheme>
where
    R: RouteConfig,
    R::Scheme: SupportsPasswordReset,
{
    struct WithPasswordResetRoute<R: RouteConfig> {
        instance: R,
    }

    impl<R> RouteConfig for WithPasswordResetRoute<R>
    where
        R: RouteConfig,
        R::Scheme: SupportsPasswordReset,
    {
        type Scheme = R::Scheme;

        fn get_routers(&mut self) -> Routers<Self::Scheme> {
            self.instance.get_routers()
        }

        fn set_routers(&mut self, routers: Routers<Self::Scheme>) {
            self.instance.set_routers(routers)
        }

        fn build(self, assets_dir: String, scheme: Self::Scheme) -> Router {
            self.instance.build(assets_dir, scheme)
        }

        fn login_route(mut self, login_path: &str, verify_token_path: &str) -> Self {
            self.instance = self.instance.login_route(login_path, verify_token_path);
            self
        }

        fn logout_route(mut self, logout_path: &str) -> Self {
            self.instance = self.instance.logout_route(logout_path);
            self
        }

        fn with_signup_route(mut self, signup_path: Option<&str>) -> Self {
            self.instance = self.instance.with_signup_route(signup_path);
            self
        }

        fn with_2fa_route(mut self, verify_2fa_path: Option<&str>) -> Self {
            self.instance = self.instance.with_2fa_route(verify_2fa_path);
            self
        }

        fn with_password_reset_route(
            mut self,
            initiate_path: Option<&str>,
            complete_path: Option<&str>,
        ) -> Self {
            if let (Some(initiate), Some(complete)) = (initiate_path, complete_path) {
                let mut routers = self.get_routers();
                routers.main_router = routers
                    .main_router
                    .route(
                        initiate,
                        post(crate::routes::initiate_password_reset::<Self::Scheme>),
                    )
                    .route(
                        complete,
                        post(crate::routes::complete_password_reset::<Self::Scheme>),
                    );
                self.set_routers(routers);
            }
            self
        }

        fn with_email_verification_route(mut self, verify_path: Option<&str>) -> Self {
            self.instance = self.instance.with_email_verification_route(verify_path);
            self
        }
    }

    WithPasswordResetRoute { instance }
}

// ============================================================================
// WithEmailVerificationRoute
// ============================================================================

pub fn with_email_verification_route<R>(instance: R) -> impl RouteConfig<Scheme = R::Scheme>
where
    R: RouteConfig,
    R::Scheme: RequiresEmailVerification,
    <R::Scheme as RequiresEmailVerification>::EmailVerificationError: IntoStatusMessage,
{
    struct WithEmailVerificationRoute<R: RouteConfig> {
        instance: R,
    }

    impl<R> RouteConfig for WithEmailVerificationRoute<R>
    where
        R: RouteConfig,
        R::Scheme: RequiresEmailVerification,
        <R::Scheme as RequiresEmailVerification>::EmailVerificationError: IntoStatusMessage,
    {
        type Scheme = R::Scheme;

        fn get_routers(&mut self) -> Routers<Self::Scheme> {
            self.instance.get_routers()
        }

        fn set_routers(&mut self, routers: Routers<Self::Scheme>) {
            self.instance.set_routers(routers)
        }

        fn build(self, assets_dir: String, scheme: Self::Scheme) -> Router {
            self.instance.build(assets_dir, scheme)
        }

        fn login_route(mut self, login_path: &str, verify_token_path: &str) -> Self {
            self.instance = self.instance.login_route(login_path, verify_token_path);
            self
        }

        fn logout_route(mut self, logout_path: &str) -> Self {
            self.instance = self.instance.logout_route(logout_path);
            self
        }

        fn with_signup_route(mut self, signup_path: Option<&str>) -> Self {
            self.instance = self.instance.with_signup_route(signup_path);
            self
        }

        fn with_2fa_route(mut self, verify_2fa_path: Option<&str>) -> Self {
            self.instance = self.instance.with_2fa_route(verify_2fa_path);
            self
        }

        fn with_password_reset_route(
            mut self,
            initiate_path: Option<&str>,
            complete_path: Option<&str>,
        ) -> Self {
            self.instance = self
                .instance
                .with_password_reset_route(initiate_path, complete_path);
            self
        }

        fn with_email_verification_route(mut self, verify_path: Option<&str>) -> Self {
            if let Some(path) = verify_path {
                let mut routers = self.get_routers();
                routers.main_router = routers
                    .main_router
                    .route(path, post(crate::routes::verify_email::<Self::Scheme>));
                self.set_routers(routers);
            }
            self
        }
    }

    WithEmailVerificationRoute { instance }
}
