use axum::{
    Router,
    routing::{delete, post},
};
use tempered_core::{
    AuthValidator, AuthenticationScheme, HttpAuthenticationScheme, HttpElevationScheme,
    IntoStatusMessage, SupportsAccountDeletion, SupportsElevation, SupportsPasswordChange,
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

    // Path customization methods
    fn set_login_path(&mut self, path: String);
    fn set_logout_path(&mut self, path: String);
    fn set_verify_token_path(&mut self, path: String);

    // Access to scheme and assets
    fn get_scheme(&self) -> &Self::Scheme;
    fn get_assets_dir(&self) -> &str;

    // Build method - consumes self and returns final Router
    fn build(self) -> Router;

    // Required routes (always present)
    fn login_route(self) -> Self;
    fn logout_route(self) -> Self;
    fn with_verify_token_route(self) -> Self;

    // Optional routes (default no-op implementations)
    fn with_signup_route(self) -> Self {
        self
    }
    fn with_2fa_route(self) -> Self {
        self
    }
    fn with_elevate_route(self) -> Self {
        self
    }
    fn with_verify_elevated_token_route(self) -> Self {
        self
    }
    fn with_change_password_route(self) -> Self {
        self
    }
    fn with_delete_account_route(self) -> Self {
        self
    }
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

        fn with_verify_token_route(mut self) -> Self {
            self.instance = self.instance.with_verify_token_route();
            self
        }

        fn with_verify_elevated_token_route(mut self) -> Self {
            self.instance = self.instance.with_verify_elevated_token_route();
            self
        }

        fn with_change_password_route(mut self) -> Self {
            self.instance = self.instance.with_change_password_route();
            self
        }

        fn with_delete_account_route(mut self) -> Self {
            self.instance = self.instance.with_delete_account_route();
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

        fn with_verify_token_route(mut self) -> Self {
            self.instance = self.instance.with_verify_token_route();
            self
        }

        fn with_verify_elevated_token_route(mut self) -> Self {
            self.instance = self.instance.with_verify_elevated_token_route();
            self
        }

        fn with_change_password_route(mut self) -> Self {
            self.instance = self.instance.with_change_password_route();
            self
        }

        fn with_delete_account_route(mut self) -> Self {
            self.instance = self.instance.with_delete_account_route();
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

pub fn with_elevate_route<R>(
    instance: R,
    elevate_path: &str,
    verify_elevated_token_path: &str,
) -> impl RouteConfig<Scheme = R::Scheme>
where
    R: RouteConfig,
    R::Scheme: HttpElevationScheme + SupportsElevation,
    <R::Scheme as AuthenticationScheme>::Validator:
        AuthValidator<RequestParts = http::request::Parts>,
    <<R::Scheme as AuthenticationScheme>::Validator as AuthValidator>::Error: IntoStatusMessage,
    <R::Scheme as SupportsElevation>::ElevatedValidator:
        AuthValidator<RequestParts = http::request::Parts>,
    <<R::Scheme as SupportsElevation>::ElevatedValidator as AuthValidator>::Error:
        IntoStatusMessage,
{
    struct WithElevateRoute<R: RouteConfig> {
        instance: R,
        elevate_path: String,
        verify_elevated_token_path: String,
    }

    impl<R> RouteConfig for WithElevateRoute<R>
    where
        R: RouteConfig,
        R::Scheme: HttpElevationScheme + SupportsElevation,
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

            // Get routers from the chain
            let mut config = self.instance;
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
            self.instance = self.instance.logout_route();
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

            // Only initialize if not already done
            if routers.elevated_router.is_none() {
                // Initialize elevated router
                routers.elevated_router = Some(Router::new());

                // Add elevate route to validated router
                routers.validated_router = routers.validated_router.route(
                    &self.elevate_path,
                    post(crate::routes::elevate::<Self::Scheme>),
                );

                // Add verify_elevated_token route to elevated router
                if let Some(ref mut elevated_router) = routers.elevated_router {
                    *elevated_router = elevated_router.clone().route(
                        &self.verify_elevated_token_path,
                        post(crate::routes::verify_elevated_token::<Self::Scheme>),
                    );
                }
            }

            self.set_routers(routers);
            self
        }

        fn with_verify_token_route(mut self) -> Self {
            self.instance = self.instance.with_verify_token_route();
            self
        }

        fn with_verify_elevated_token_route(mut self) -> Self {
            let mut routers = self.get_routers();
            if let Some(ref mut elevated_router) = routers.elevated_router {
                *elevated_router = elevated_router.clone().route(
                    &self.verify_elevated_token_path,
                    post(crate::routes::verify_elevated_token::<Self::Scheme>),
                );
            }
            self.set_routers(routers);
            self
        }

        fn with_change_password_route(mut self) -> Self {
            self.instance = self.instance.with_change_password_route();
            self
        }

        fn with_delete_account_route(mut self) -> Self {
            self.instance = self.instance.with_delete_account_route();
            self
        }
    }

    WithElevateRoute {
        instance,
        elevate_path: elevate_path.to_string(),
        verify_elevated_token_path: verify_elevated_token_path.to_string(),
    }
}

// ============================================================================
// WithChangePasswordRoute
// ============================================================================

pub fn with_change_password_route<R>(
    instance: R,
    path: &str,
) -> impl RouteConfig<Scheme = R::Scheme>
where
    R: RouteConfig,
    R::Scheme: HttpAuthenticationScheme + SupportsPasswordChange,
{
    struct WithChangePasswordRoute<R: RouteConfig> {
        instance: R,
        change_password_path: String,
    }

    impl<R> RouteConfig for WithChangePasswordRoute<R>
    where
        R: RouteConfig,
        R::Scheme: HttpAuthenticationScheme + SupportsPasswordChange,
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
            self.instance = self.instance.with_2fa_route();
            self
        }

        fn with_elevate_route(mut self) -> Self {
            self.instance = self.instance.with_elevate_route();
            self
        }

        fn with_verify_token_route(mut self) -> Self {
            self.instance = self.instance.with_verify_token_route();
            self
        }

        fn with_verify_elevated_token_route(mut self) -> Self {
            self.instance = self.instance.with_verify_elevated_token_route();
            self
        }

        fn with_change_password_route(mut self) -> Self {
            let mut routers = self.get_routers();
            if let Some(ref mut elevated_router) = routers.elevated_router {
                *elevated_router = elevated_router.clone().route(
                    &self.change_password_path,
                    post(crate::routes::change_password::<Self::Scheme>),
                );
            }
            self.set_routers(routers);
            self
        }

        fn with_delete_account_route(mut self) -> Self {
            self.instance = self.instance.with_delete_account_route();
            self
        }
    }

    WithChangePasswordRoute {
        instance,
        change_password_path: path.to_string(),
    }
}

// ============================================================================
// WithDeleteAccountRoute
// ============================================================================

pub fn with_delete_account_route<R>(instance: R, path: &str) -> impl RouteConfig<Scheme = R::Scheme>
where
    R: RouteConfig,
    R::Scheme: HttpAuthenticationScheme + SupportsAccountDeletion,
{
    struct WithDeleteAccountRoute<R: RouteConfig> {
        instance: R,
        delete_account_path: String,
    }

    impl<R> RouteConfig for WithDeleteAccountRoute<R>
    where
        R: RouteConfig,
        R::Scheme: HttpAuthenticationScheme + SupportsAccountDeletion,
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
            self.instance = self.instance.with_2fa_route();
            self
        }

        fn with_elevate_route(mut self) -> Self {
            self.instance = self.instance.with_elevate_route();
            self
        }

        fn with_verify_token_route(mut self) -> Self {
            self.instance = self.instance.with_verify_token_route();
            self
        }

        fn with_verify_elevated_token_route(mut self) -> Self {
            self.instance = self.instance.with_verify_elevated_token_route();
            self
        }

        fn with_change_password_route(mut self) -> Self {
            self.instance = self.instance.with_change_password_route();
            self
        }

        fn with_delete_account_route(mut self) -> Self {
            let mut routers = self.get_routers();
            if let Some(ref mut elevated_router) = routers.elevated_router {
                *elevated_router = elevated_router.clone().route(
                    &self.delete_account_path,
                    delete(crate::routes::delete_account::<Self::Scheme>),
                );
            }
            self.set_routers(routers);
            self
        }
    }

    WithDeleteAccountRoute {
        instance,
        delete_account_path: path.to_string(),
    }
}
