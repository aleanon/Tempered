use axum::{Router, routing::post};
use tempered_core::{
    AuthValidator, AuthenticationScheme, HttpAuthenticationScheme, HttpElevationScheme,
    IntoStatusMessage, SupportsElevation, SupportsRegistration, SupportsTokenRevocation,
    SupportsTwoFactor,
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

    // Path customization methods
    fn set_login_path(&mut self, path: String);
    fn set_logout_path(&mut self, path: String);
    fn set_verify_token_path(&mut self, path: String);
    fn get_logout_path(&self) -> String;

    // Access to scheme and assets
    fn get_scheme(&self) -> &Self::Scheme;
    fn get_assets_dir(&self) -> &str;

    // Build method - consumes self and returns final Router
    fn build(self) -> Router;

    // Required routes (always present)
    fn login_route(self) -> Self;
    fn logout_route(self) -> Self;

    // Optional routes (default no-op implementations)
    fn with_signup_route(self) -> Self;
    fn with_2fa_route(self) -> Self;
    fn with_elevate_route(self) -> Self;
}

// ============================================================================
// WithSignupRoute
// ============================================================================

pub fn with_signup_route<R>(instance: R, path: &str) -> impl RouteConfig<Scheme = R::Scheme>
where
    R: RouteConfig,
    R::Scheme: SupportsRegistration,
    <R::Scheme as SupportsRegistration>::RegistrationError: IntoStatusMessage,
{
    struct WithSignupRoute<R: RouteConfig> {
        instance: R,
        signup_path: String,
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

        fn set_login_path(&mut self, path: String) {
            self.instance.set_login_path(path)
        }

        fn set_logout_path(&mut self, path: String) {
            self.instance.set_logout_path(path)
        }

        fn set_verify_token_path(&mut self, path: String) {
            self.instance.set_verify_token_path(path);
        }

        fn get_logout_path(&self) -> String {
            self.instance.get_logout_path()
        }

        fn get_scheme(&self) -> &Self::Scheme {
            self.instance.get_scheme()
        }

        fn get_assets_dir(&self) -> &str {
            self.instance.get_assets_dir()
        }

        fn build(self) -> Router {
            self.instance.build()
        }

        fn login_route(mut self) -> Self {
            self.instance = self.instance.login_route();
            self
        }

        fn logout_route(mut self) -> Self {
            self.instance = self.instance.logout_route();
            self
        }

        fn with_signup_route(mut self) -> Self {
            let mut routers = self.get_routers();
            routers.main_router = routers.main_router.route(
                &self.signup_path,
                post(crate::routes::signup::<Self::Scheme>),
            );
            self.set_routers(routers);
            self
        }

        fn with_2fa_route(mut self) -> Self {
            self.instance = self.instance.with_2fa_route();
            self
        }

        fn with_elevate_route(mut self) -> Self {
            self.instance = self.instance.with_elevate_route();
            self
        }
    }

    WithSignupRoute {
        instance,
        signup_path: path.to_string(),
    }
}

// ============================================================================
// With2FaRoute
// ============================================================================

pub fn with_2fa_route<R>(instance: R, path: &str) -> impl RouteConfig<Scheme = R::Scheme>
where
    R: RouteConfig,
    R::Scheme: HttpAuthenticationScheme + SupportsTwoFactor,
    <R::Scheme as SupportsTwoFactor>::TwoFactorError: IntoStatusMessage,
{
    struct With2FaRoute<R: RouteConfig> {
        instance: R,
        verify_2fa_path: String,
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

        fn set_login_path(&mut self, path: String) {
            self.instance.set_login_path(path)
        }

        fn set_logout_path(&mut self, path: String) {
            self.instance.set_logout_path(path)
        }

        fn set_verify_token_path(&mut self, path: String) {
            self.instance.set_verify_token_path(path);
        }

        fn get_logout_path(&self) -> String {
            self.instance.get_logout_path()
        }

        fn get_scheme(&self) -> &Self::Scheme {
            self.instance.get_scheme()
        }

        fn get_assets_dir(&self) -> &str {
            self.instance.get_assets_dir()
        }

        fn build(self) -> Router {
            self.instance.build()
        }

        fn login_route(mut self) -> Self {
            self.instance = self.instance.login_route();
            self
        }

        fn logout_route(mut self) -> Self {
            self.instance = self.instance.logout_route();
            self
        }

        fn with_signup_route(mut self) -> Self {
            self.instance = self.instance.with_signup_route();
            self
        }

        fn with_2fa_route(mut self) -> Self {
            let mut routers = self.get_routers();
            routers.main_router = routers.main_router.route(
                &self.verify_2fa_path,
                post(crate::routes::verify_2fa::<Self::Scheme>),
            );
            self.set_routers(routers);
            self
        }

        fn with_elevate_route(mut self) -> Self {
            self.instance = self.instance.with_elevate_route();
            self
        }
    }

    With2FaRoute {
        instance,
        verify_2fa_path: path.to_string(),
    }
}

// ============================================================================
// WithElevateRoute
// ============================================================================

pub fn with_elevate_route<R, F>(
    instance: R,
    elevate_path: &str,
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
        elevate_path: String,
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

        fn set_login_path(&mut self, path: String) {
            self.instance.set_login_path(path)
        }

        fn set_logout_path(&mut self, path: String) {
            self.instance.set_logout_path(path)
        }

        fn set_verify_token_path(&mut self, path: String) {
            self.instance.set_verify_token_path(path)
        }

        fn get_logout_path(&self) -> String {
            self.instance.get_logout_path()
        }

        fn get_scheme(&self) -> &Self::Scheme {
            self.instance.get_scheme()
        }

        fn get_assets_dir(&self) -> &str {
            self.instance.get_assets_dir()
        }

        fn build(self) -> Router {
            use axum::middleware;
            use tower_http::services::{ServeDir, ServeFile};

            let scheme = self.instance.get_scheme().clone();
            let assets_dir = self.instance.get_assets_dir().to_string();

            // Get routers from the chain - routes are already registered by Instance::build()
            let mut config = self
                .login_route()
                .logout_route()
                .with_signup_route()
                .with_2fa_route()
                .with_elevate_route();

            let routers = config.get_routers();

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

        fn login_route(mut self) -> Self {
            self.instance = self.instance.login_route();
            self
        }

        fn logout_route(mut self) -> Self {
            // Override to use logout_with_elevation since this wrapper supports elevation
            let logout_path = self.get_logout_path();
            let mut routers = self.get_routers();

            // Register logout route with elevation support
            routers.validated_router = routers.validated_router.route(
                &logout_path,
                post(crate::routes::logout_with_elevation::<Self::Scheme>),
            );

            self.set_routers(routers);
            self
        }

        fn with_signup_route(mut self) -> Self {
            self.instance = self.instance.with_signup_route();
            self
        }

        fn with_2fa_route(mut self) -> Self {
            self.instance = self.instance.with_2fa_route();
            self
        }

        fn with_elevate_route(mut self) -> Self {
            let mut routers = self.get_routers();

            // Use the pre-configured elevated router from the closure
            if routers.elevated_router.is_none() && self.elevated_router.is_some() {
                routers.elevated_router = self.elevated_router.take();

                // Add elevate route to validated router
                routers.validated_router = routers.validated_router.route(
                    &self.elevate_path,
                    post(crate::routes::elevate::<Self::Scheme>),
                );
            }

            self.set_routers(routers);
            self
        }
    }

    // Create ElevatedRouter and pass to closure for configuration
    let elevated_router = crate::ElevatedRouter::new(verify_elevated_token_path.to_string());
    let configured_elevated = configure(elevated_router);

    WithElevateRoute {
        instance,
        elevate_path: elevate_path.to_string(),
        elevated_router: Some(configured_elevated.0),
    }
}
