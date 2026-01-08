use std::marker::PhantomData;

use axum::{Router, routing::post};
use tempered_core::{
    AuthValidator, AuthenticationScheme, HttpAuthenticationScheme, HttpElevationScheme,
    IntoStatusMessage, SupportsElevation, SupportsRegistration, SupportsTwoFactor,
};
use tokio::net::TcpListener;

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
        login_path: String,
        logout_path: String,
        verify_token_path: String,
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

        fn set_login_path(&mut self, path: String) {
            self.login_path = path;
        }

        fn set_logout_path(&mut self, path: String) {
            self.logout_path = path;
        }

        fn set_verify_token_path(&mut self, path: String) {
            self.verify_token_path = path;
        }

        fn get_logout_path(&self) -> String {
            self.logout_path.clone()
        }

        fn build(self, assets_dir: String, scheme: S) -> Router {
            use axum::middleware;
            use tower_http::services::{ServeDir, ServeFile};

            // Register required routes by calling trait methods
            let configured = self
                .login_route()
                .logout_route()
                .with_signup_route()
                .with_2fa_route()
                .with_elevate_route();

            // Apply middleware to validated routes
            let validated_router =
                configured
                    .validated_router
                    .layer(middleware::from_fn_with_state(
                        scheme.clone(),
                        crate::middleware::validate_token::<S>,
                    ));

            // Merge all routers
            let router = configured.main_router.merge(validated_router);

            // Static assets
            let assets_service = ServeDir::new(&assets_dir)
                .not_found_service(ServeFile::new(format!("{}/index.html", assets_dir)));

            // Final router with state and assets
            router.with_state(scheme).fallback_service(assets_service)
        }

        fn login_route(mut self) -> Self {
            self.main_router = self
                .main_router
                .route(&self.login_path, post(crate::routes::login::<S>));
            self.validated_router = self.validated_router.route(
                &self.verify_token_path,
                post(crate::routes::verify_token::<Self::Scheme>),
            );
            self
        }

        fn logout_route(mut self) -> Self {
            self.validated_router = self
                .validated_router
                .route(&self.logout_path, post(crate::routes::logout::<S>));
            self
        }

        fn with_signup_route(self) -> Self {
            self
        }

        fn with_2fa_route(self) -> Self {
            self
        }

        fn with_elevate_route(self) -> Self {
            self
        }
    }

    let instance = Instance {
        _schema: PhantomData,
        login_path: "/login".to_string(),
        logout_path: "/logout".to_string(),
        verify_token_path: "/verify-token".to_string(),
        main_router: Router::new(),
        validated_router: Router::new(),
        elevated_router: None,
    };

    AuthService {
        instance,
        assets_dir,
        schema,
    }
}

pub struct AuthService<R: RouteConfig> {
    instance: R,
    assets_dir: String,
    schema: R::Scheme,
}

impl<R> AuthService<R>
where
    R: RouteConfig,
{
    /// Overrides the default login path
    pub fn login_route(mut self, path: &str) -> Self {
        validate_path(path);
        self.instance.set_login_path(path.to_string());
        self
    }

    /// Overrides the default logout path
    pub fn logout_route(mut self, path: &str) -> Self {
        validate_path(path);
        self.instance.set_logout_path(path.to_string());
        self
    }

    /// Overrides the default verify token path
    pub fn verify_token_route(mut self, path: &str) -> Self {
        validate_path(path);
        self.instance.set_verify_token_path(path.to_string());
        self
    }

    /// Runs the Authentication Service as a standalone axum server
    pub async fn run(self, listener: TcpListener) -> Result<(), std::io::Error> {
        let router = self.instance.build(self.assets_dir, self.schema);

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
            instance: route_config::with_signup_route(self.instance, path),
            assets_dir: self.assets_dir,
            schema: self.schema,
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
            instance: route_config::with_2fa_route(self.instance, path),
            assets_dir: self.assets_dir,
            schema: self.schema,
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
                elevate_path,
                verify_elevated_token_path,
                configure,
            ),
            assets_dir: self.assets_dir,
            schema: self.schema,
        }
    }
}

impl<R> Into<Router> for AuthService<R>
where
    R: RouteConfig,
{
    fn into(self) -> Router {
        self.instance.build(self.assets_dir, self.schema)
    }
}

fn validate_path(path: &str) {
    if path.trim().is_empty() {
        panic!("Route path cannot be empty or whitespace-only");
    }
}
