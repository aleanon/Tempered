use axum::{Router, routing::post};
use tempered_core::{
    AuthValidator, AuthenticationScheme, HttpAuthenticationScheme, HttpElevationScheme,
    IntoStatusMessage, RequiresEmailVerification, SupportsElevation, SupportsPasswordReset,
    SupportsRegistration, SupportsTwoFactor,
};

pub struct Routers<Scheme> {
    pub main_router: Router<Scheme>,
    pub validated_router: Router<Scheme>,
    pub elevated_router: Option<Router<Scheme>>,
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
    fn with_elevate_route(self, _elevate_path: Option<&str>) -> Self {
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

        fn with_elevate_route(mut self, elevate_path: Option<&str>) -> Self {
            self.instance = self.instance.with_elevate_route(elevate_path);
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

        fn with_elevate_route(mut self, elevate_path: Option<&str>) -> Self {
            self.instance = self.instance.with_elevate_route(elevate_path);
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
// WithElevateRoute
// ============================================================================

pub fn with_elevate_route<R, F>(
    instance: R,
    verify_elevated_token_path: &str,
    configure: F,
) -> impl RouteConfig<Scheme = R::Scheme>
where
    R: RouteConfig,
    R::Scheme: HttpElevationScheme,
    <R::Scheme as AuthenticationScheme>::Validator:
        AuthValidator<RequestParts = http::request::Parts>,
    <<R::Scheme as AuthenticationScheme>::Validator as AuthValidator>::Error: IntoStatusMessage,
    <R::Scheme as SupportsElevation>::ElevatedValidator:
        AuthValidator<RequestParts = http::request::Parts>,
    <<R::Scheme as SupportsElevation>::ElevatedValidator as AuthValidator>::Error:
        IntoStatusMessage,
    F: FnOnce(crate::ElevatedRouter<R::Scheme>) -> crate::ElevatedRouter<R::Scheme>,
{
    struct WithElevateRoute<R: RouteConfig> {
        instance: R,
        elevated_router: Option<Router<R::Scheme>>,
    }

    impl<R> RouteConfig for WithElevateRoute<R>
    where
        R: RouteConfig,
        R::Scheme: HttpElevationScheme,
        <R::Scheme as AuthenticationScheme>::Validator:
            AuthValidator<RequestParts = http::request::Parts>,
        <<R::Scheme as AuthenticationScheme>::Validator as AuthValidator>::Error: IntoStatusMessage,
        <R::Scheme as SupportsElevation>::ElevatedValidator:
            AuthValidator<RequestParts = http::request::Parts>,
        <<R::Scheme as SupportsElevation>::ElevatedValidator as AuthValidator>::Error:
            IntoStatusMessage,
    {
        type Scheme = R::Scheme;

        fn get_routers(&mut self) -> Routers<Self::Scheme> {
            self.instance.get_routers()
        }

        fn set_routers(&mut self, routers: Routers<Self::Scheme>) {
            self.instance.set_routers(routers)
        }

        fn build(mut self, assets_dir: String, scheme: Self::Scheme) -> Router {
            use axum::middleware;
            use tower_http::services::{ServeDir, ServeFile};

            // Get the routers that have been configured with all routes
            let routers = self.get_routers();

            // Apply middleware to validated routes
            let validated_router = routers
                .validated_router
                .layer(middleware::from_fn_with_state(
                    scheme.clone(),
                    crate::middleware::validate_token::<Self::Scheme>,
                ));

            // Apply middleware to elevated routes if present
            let router = if let Some(elevated_router) = routers.elevated_router {
                let elevated_router = elevated_router.layer(middleware::from_fn_with_state(
                    scheme.clone(),
                    crate::middleware::validate_elevated_token::<Self::Scheme>,
                ));

                routers
                    .main_router
                    .merge(validated_router)
                    .merge(elevated_router)
            } else {
                routers.main_router.merge(validated_router)
            };

            // Static assets
            let assets_service = ServeDir::new(&assets_dir)
                .not_found_service(ServeFile::new(format!("{}/index.html", assets_dir)));

            // Final router with state and assets
            router.with_state(scheme).fallback_service(assets_service)
        }

        fn login_route(mut self, login_path: &str, verify_token_path: &str) -> Self {
            self.instance = self.instance.login_route(login_path, verify_token_path);
            self
        }

        fn logout_route(mut self, logout_path: &str) -> Self {
            // Override to use logout_with_elevation since this wrapper supports elevation
            let mut routers = self.get_routers();

            // Register logout route with elevation support
            routers.validated_router = routers.validated_router.route(
                logout_path,
                post(crate::routes::logout_with_elevation::<Self::Scheme>),
            );

            self.set_routers(routers);
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

        fn with_elevate_route(mut self, elevate_path: Option<&str>) -> Self {
            if let Some(path) = elevate_path {
                let mut routers = self.get_routers();

                // Use the pre-configured elevated router from the closure
                if routers.elevated_router.is_none() && self.elevated_router.is_some() {
                    routers.elevated_router = self.elevated_router.take();

                    // Add elevate route to validated router
                    routers.validated_router = routers
                        .validated_router
                        .route(path, post(crate::routes::elevate::<Self::Scheme>));
                }

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

    // Create ElevatedRouter and pass to closure for configuration
    let elevated_router = crate::ElevatedRouter::new(verify_elevated_token_path.to_string());
    let configured_elevated = configure(elevated_router);

    WithElevateRoute {
        instance,
        elevated_router: Some(configured_elevated.0),
    }
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

        fn with_elevate_route(mut self, elevate_path: Option<&str>) -> Self {
            self.instance = self.instance.with_elevate_route(elevate_path);
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

        fn with_elevate_route(mut self, elevate_path: Option<&str>) -> Self {
            self.instance = self.instance.with_elevate_route(elevate_path);
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
