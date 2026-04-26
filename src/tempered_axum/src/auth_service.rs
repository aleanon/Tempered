use std::marker::PhantomData;

use axum::{Router, routing::post};
use tempered_core::{
    AuthValidator, AuthenticationScheme, HttpAuthenticationScheme, HttpElevationScheme,
    IntoStatusMessage, SupportsElevation, SupportsPasswordReset, SupportsRegistration,
    SupportsTwoFactor,
};
use tokio::net::TcpListener;
use tracing::info;

use crate::route_config::{self, RouteConfig, Routers};

pub fn auth_service<S>(schema: S, assets_dir: String) -> AuthService<impl RouteConfig<Scheme = S>>
where
    S: HttpAuthenticationScheme<LogoutOutput = String> + Send + Sync + Clone + 'static,
    S::AuthError: IntoStatusMessage,
    <S as tempered_core::AuthenticationScheme>::Validator:
        tempered_core::AuthValidator<RequestParts = http::request::Parts>,
    <<S as tempered_core::AuthenticationScheme>::Validator as tempered_core::AuthValidator>::Error:
        IntoStatusMessage,
{
    struct Instance<S> {
        _schema: PhantomData<S>,
        main_router: Router<S>,
        validated_router: Router<S>,
        elevated_router: Option<Router<S>>,
    }

    impl<S> RouteConfig for Instance<S>
    where
        S: HttpAuthenticationScheme<LogoutOutput = String> + Send + Sync + Clone + 'static,
        S::AuthError: IntoStatusMessage,
        <S as AuthenticationScheme>::Validator: AuthValidator<RequestParts = http::request::Parts>,
        <<S as AuthenticationScheme>::Validator as AuthValidator>::Error: IntoStatusMessage,
    {
        type Scheme = S;

        fn get_routers(&mut self) -> route_config::Routers<Self::Scheme> {
            Routers {
                main_router: std::mem::take(&mut self.main_router),
                validated_router: std::mem::take(&mut self.validated_router),
                elevated_router: std::mem::take(&mut self.elevated_router),
            }
        }

        fn set_routers(&mut self, routers: Routers<Self::Scheme>) {
            self.main_router = routers.main_router;
            self.validated_router = routers.validated_router;
            self.elevated_router = routers.elevated_router;
        }

        fn build(self, assets_dir: String, scheme: S) -> Router {
            use axum::middleware;
            use tower_http::services::{ServeDir, ServeFile};

            // Note: This build() should not be called directly on Instance
            // AuthService manages the build process and passes paths
            // Apply middleware to validated routes
            let validated_router = self.validated_router.layer(middleware::from_fn_with_state(
                scheme.clone(),
                crate::middleware::validate_token::<S>,
            ));

            // Merge all routers
            let router = self.main_router.merge(validated_router);

            // Static assets
            let assets_service = ServeDir::new(&assets_dir)
                .not_found_service(ServeFile::new(format!("{}/index.html", assets_dir)));

            // Final router with state and assets
            router.with_state(scheme).fallback_service(assets_service)
        }

        fn login_route(mut self, login_path: &str, verify_token_path: &str) -> Self {
            self.main_router = self
                .main_router
                .route(login_path, post(crate::routes::login::<S>));
            self.validated_router = self.validated_router.route(
                verify_token_path,
                post(crate::routes::verify_token::<Self::Scheme>),
            );
            self
        }

        fn logout_route(mut self, logout_path: &str) -> Self {
            self.validated_router = self
                .validated_router
                .route(logout_path, post(crate::routes::logout::<S>));
            self
        }
    }

    let instance = Instance {
        _schema: PhantomData,
        main_router: Router::new(),
        validated_router: Router::new(),
        elevated_router: None,
    };

    AuthService {
        instance,
        assets_dir,
        schema,
        login_path: "/login".to_string(),
        logout_path: "/logout".to_string(),
        verify_token_path: "/verify-token".to_string(),
        signup_path: None,
        verify_2fa_path: None,
        elevate_path: None,
        password_reset_initiate_path: None,
        password_reset_complete_path: None,
    }
}

pub struct AuthService<R: RouteConfig> {
    instance: R,
    assets_dir: String,
    schema: R::Scheme,
    login_path: String,
    logout_path: String,
    verify_token_path: String,
    signup_path: Option<String>,
    verify_2fa_path: Option<String>,
    elevate_path: Option<String>,
    password_reset_initiate_path: Option<String>,
    password_reset_complete_path: Option<String>,
}

impl<R> AuthService<R>
where
    R: RouteConfig,
{
    /// Overrides the default login path
    pub fn login_route(mut self, path: &str) -> Self {
        validate_path(path);
        self.login_path = path.to_string();
        self
    }

    /// Overrides the default logout path
    pub fn logout_route(mut self, path: &str) -> Self {
        validate_path(path);
        self.logout_path = path.to_string();
        self
    }

    /// Overrides the default verify token path
    pub fn verify_token_route(mut self, path: &str) -> Self {
        validate_path(path);
        self.verify_token_path = path.to_string();
        self
    }

    /// Runs the Authentication Service as a standalone axum server
    pub async fn run(self, listener: TcpListener) -> Result<(), std::io::Error> {
        // Register routes by calling trait methods with stored paths
        let configured = self
            .instance
            .login_route(&self.login_path, &self.verify_token_path)
            .logout_route(&self.logout_path)
            .with_signup_route(self.signup_path.as_deref())
            .with_2fa_route(self.verify_2fa_path.as_deref())
            .with_elevate_route(self.elevate_path.as_deref())
            .with_password_reset_route(
                self.password_reset_initiate_path.as_deref(),
                self.password_reset_complete_path.as_deref(),
            );

        let router = configured.build(self.assets_dir, self.schema);

        info!(
            "listening on {}",
            listener
                .local_addr()
                .expect("Failed to get address from listener")
        );

        axum::serve(listener, router).await
    }
}

impl<R> AuthService<R>
where
    R: RouteConfig,
    R::Scheme: SupportsRegistration,
    <R::Scheme as SupportsRegistration>::RegistrationError: IntoStatusMessage,
{
    /// Overrides the default signup route path, or adds a new route for signup
    /// if it does not already exist
    pub fn signup_route(
        self,
        path: Option<&str>,
    ) -> AuthService<impl RouteConfig<Scheme = R::Scheme>> {
        let path = path.unwrap_or("/signup");

        validate_path(&path);

        AuthService {
            instance: route_config::with_signup_route(self.instance),
            assets_dir: self.assets_dir,
            schema: self.schema,
            login_path: self.login_path,
            logout_path: self.logout_path,
            verify_token_path: self.verify_token_path,
            signup_path: Some(path.to_string()),
            verify_2fa_path: self.verify_2fa_path,
            elevate_path: self.elevate_path,
            password_reset_initiate_path: self.password_reset_initiate_path,
            password_reset_complete_path: self.password_reset_complete_path,
        }
    }
}

impl<R> AuthService<R>
where
    R: RouteConfig,
    R::Scheme: HttpAuthenticationScheme + SupportsTwoFactor,
    <R::Scheme as SupportsTwoFactor>::TwoFactorError: IntoStatusMessage,
{
    /// Adds support for two factor authentication and creates a route for verifying two factor authentication
    pub fn with_2fa(self, path: Option<&str>) -> AuthService<impl RouteConfig<Scheme = R::Scheme>> {
        let path = path.unwrap_or("/verify-2fa");

        validate_path(&path);

        AuthService {
            instance: route_config::with_2fa_route(self.instance),
            assets_dir: self.assets_dir,
            schema: self.schema,
            login_path: self.login_path,
            logout_path: self.logout_path,
            verify_token_path: self.verify_token_path,
            signup_path: self.signup_path,
            verify_2fa_path: Some(path.to_string()),
            elevate_path: self.elevate_path,
            password_reset_initiate_path: self.password_reset_initiate_path,
            password_reset_complete_path: self.password_reset_complete_path,
        }
    }
}

impl<R> AuthService<R>
where
    R: RouteConfig,
    R::Scheme: SupportsPasswordReset,
{
    /// Adds password reset routes (initiate + complete) to the service.
    pub fn with_password_reset(
        self,
        initiate_path: Option<&str>,
        complete_path: Option<&str>,
    ) -> AuthService<impl RouteConfig<Scheme = R::Scheme>> {
        let initiate_path = initiate_path.unwrap_or("/password-reset/initiate");
        let complete_path = complete_path.unwrap_or("/password-reset/complete");

        validate_path(initiate_path);
        validate_path(complete_path);

        AuthService {
            instance: route_config::with_password_reset_route(self.instance),
            assets_dir: self.assets_dir,
            schema: self.schema,
            login_path: self.login_path,
            logout_path: self.logout_path,
            verify_token_path: self.verify_token_path,
            signup_path: self.signup_path,
            verify_2fa_path: self.verify_2fa_path,
            elevate_path: self.elevate_path,
            password_reset_initiate_path: Some(initiate_path.to_string()),
            password_reset_complete_path: Some(complete_path.to_string()),
        }
    }
}

impl<R> AuthService<R>
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
    pub fn with_elevation<F>(
        self,
        elevate_path: Option<&str>,
        verify_elevated_token_path: Option<&str>,
        configure: F,
    ) -> AuthService<impl RouteConfig<Scheme = R::Scheme>>
    where
        F: FnOnce(crate::ElevatedRouter<R::Scheme>) -> crate::ElevatedRouter<R::Scheme>,
    {
        let elevate_path = elevate_path.unwrap_or("/elevate");
        let verify_elevated_token_path =
            verify_elevated_token_path.unwrap_or("/verify-elevated-token");

        validate_path(&elevate_path);
        validate_path(&verify_elevated_token_path);

        AuthService {
            instance: route_config::with_elevate_route(
                self.instance,
                verify_elevated_token_path,
                configure,
            ),
            assets_dir: self.assets_dir,
            schema: self.schema,
            login_path: self.login_path,
            logout_path: self.logout_path,
            verify_token_path: self.verify_token_path,
            signup_path: self.signup_path,
            verify_2fa_path: self.verify_2fa_path,
            elevate_path: Some(elevate_path.to_string()),
            password_reset_initiate_path: self.password_reset_initiate_path,
            password_reset_complete_path: self.password_reset_complete_path,
        }
    }
}

impl<R> Into<Router> for AuthService<R>
where
    R: RouteConfig,
{
    fn into(self) -> Router {
        // Register routes by calling trait methods with stored paths
        let configured = self
            .instance
            .login_route(&self.login_path, &self.verify_token_path)
            .logout_route(&self.logout_path)
            .with_signup_route(self.signup_path.as_deref())
            .with_2fa_route(self.verify_2fa_path.as_deref())
            .with_elevate_route(self.elevate_path.as_deref())
            .with_password_reset_route(
                self.password_reset_initiate_path.as_deref(),
                self.password_reset_complete_path.as_deref(),
            );

        configured.build(self.assets_dir, self.schema)
    }
}

fn validate_path(path: &str) {
    if path.trim().is_empty() {
        panic!("Route path cannot be empty or whitespace-only");
    }
}
