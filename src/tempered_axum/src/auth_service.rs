use axum::{Router, routing::post};
use tempered_core::{
    AuthValidator, AuthenticationScheme, HttpAuthenticationScheme, HttpElevationScheme,
    IntoStatusMessage, SupportsAccountDeletion, SupportsElevation, SupportsPasswordChange,
    SupportsRegistration, SupportsTokenRevocation, SupportsTwoFactor,
};
use tokio::net::TcpListener;

use crate::route_config::{self, RouteConfig, Routers};

pub fn auth_service<S>(schema: S, assets_dir: String) -> AuthService<impl RouteConfig<Scheme = S>>
where
    S: HttpAuthenticationScheme + SupportsTokenRevocation + Send + Sync + Clone + 'static,
    S::AuthError: IntoStatusMessage,
    <S as tempered_core::AuthenticationScheme>::Validator:
        tempered_core::AuthValidator<RequestParts = http::request::Parts>,
    <<S as tempered_core::AuthenticationScheme>::Validator as tempered_core::AuthValidator>::Error:
        IntoStatusMessage,
{
    struct Instance<S> {
        schema: S,
        assets_dir: String,
        login_path: String,
        logout_path: String,
        verify_token_path: String,
        main_router: Router<S>,
        validated_router: Router<S>,
        elevated_router: Option<Router<S>>,
    }

    impl<S> RouteConfig for Instance<S>
    where
        S: HttpAuthenticationScheme + SupportsTokenRevocation + Send + Sync + Clone + 'static,
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

        fn get_scheme(&self) -> &Self::Scheme {
            &self.schema
        }

        fn get_assets_dir(&self) -> &str {
            &self.assets_dir
        }

        fn build(self) -> Router {
            use axum::middleware;
            use tower_http::services::{ServeDir, ServeFile};

            // Apply middleware to validated routes
            let validated_router = self.validated_router.layer(middleware::from_fn_with_state(
                self.schema.clone(),
                crate::middleware::validate_token::<S>,
            ));

            // Merge all routers
            let router = self.main_router.merge(validated_router);

            // Static assets
            let assets_service = ServeDir::new(&self.assets_dir)
                .not_found_service(ServeFile::new(format!("{}/index.html", self.assets_dir)));

            // Final router with state and assets
            router
                .with_state(self.schema)
                .fallback_service(assets_service)
        }

        fn login_route(mut self) -> Self {
            self.main_router = self
                .main_router
                .route(&self.login_path, post(crate::routes::login::<S>));
            self
        }

        fn logout_route(mut self) -> Self {
            self.main_router = self
                .main_router
                .route(&self.logout_path, post(crate::routes::logout::<S>));
            self
        }

        fn with_verify_token_route(mut self) -> Self {
            let mut routers = self.get_routers();
            routers.validated_router = routers.validated_router.route(
                &self.verify_token_path,
                post(crate::routes::verify_token::<Self::Scheme>),
            );
            self.set_routers(routers);
            self
        }
    }

    let instance = Instance {
        schema,
        assets_dir,
        login_path: "/login".to_string(),
        logout_path: "/logout".to_string(),
        verify_token_path: "/verify-token".to_string(),
        main_router: Router::new(),
        validated_router: Router::new(),
        elevated_router: None,
    };

    AuthService { instance }
}

pub struct AuthService<R> {
    instance: R,
}

impl<R> AuthService<R>
where
    R: RouteConfig,
{
    pub fn with_login_path(mut self, path: &str) -> Self {
        validate_path(path);
        self.instance.set_login_path(path.to_string());
        self
    }

    pub fn with_logout_path(mut self, path: &str) -> Self {
        validate_path(path);
        self.instance.set_logout_path(path.to_string());
        self
    }

    pub fn with_verify_token_path(mut self, path: &str) -> Self {
        validate_path(path);
        self.instance.set_verify_token_path(path.to_string());
        self
    }

    pub async fn run(self, listener: TcpListener) -> Result<(), std::io::Error> {
        let router = self.instance.build();

        axum::serve(listener, router).await
    }
}

impl<R> AuthService<R>
where
    R: RouteConfig,
    R::Scheme: SupportsRegistration,
    <R::Scheme as SupportsRegistration>::RegistrationError: IntoStatusMessage,
{
    pub fn with_registration(
        self,
        path: Option<&str>,
    ) -> AuthService<impl RouteConfig<Scheme = R::Scheme>> {
        let path = path.unwrap_or("/signup");

        validate_path(&path);

        AuthService {
            instance: route_config::with_signup_route(self.instance, path),
        }
    }
}

impl<R> AuthService<R>
where
    R: RouteConfig,
    R::Scheme: HttpAuthenticationScheme + SupportsTwoFactor,
    <R::Scheme as SupportsTwoFactor>::TwoFactorError: IntoStatusMessage,
{
    pub fn with_2fa(self, path: Option<&str>) -> AuthService<impl RouteConfig<Scheme = R::Scheme>> {
        let path = path.unwrap_or("/verify-2fa");

        validate_path(&path);

        AuthService {
            instance: route_config::with_2fa_route(self.instance, path),
        }
    }
}

impl<R> AuthService<R>
where
    R: RouteConfig,
    R::Scheme: HttpElevationScheme + SupportsElevation,
    <R::Scheme as tempered_core::AuthenticationScheme>::Validator:
        tempered_core::AuthValidator<RequestParts = http::request::Parts>,
    <<R::Scheme as tempered_core::AuthenticationScheme>::Validator as tempered_core::AuthValidator>::Error:
        IntoStatusMessage,
    <R::Scheme as SupportsElevation>::ElevatedValidator:
        tempered_core::AuthValidator<RequestParts = http::request::Parts>,
    <<R::Scheme as SupportsElevation>::ElevatedValidator as tempered_core::AuthValidator>::Error:
        IntoStatusMessage,
{
    pub fn with_elevation(
        self,
        elevate_path: Option<&str>,
        verify_elevated_token_path: Option<&str>,
    ) -> AuthService<impl RouteConfig<Scheme = R::Scheme>> {
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
            ),
        }
    }
}

impl<R> AuthService<R>
where
    R: RouteConfig,
    R::Scheme: HttpAuthenticationScheme + SupportsPasswordChange,
{
    pub fn with_change_password(
        self,
        path: Option<&str>,
    ) -> AuthService<impl RouteConfig<Scheme = R::Scheme>> {
        let path = path.unwrap_or("/change-password");

        validate_path(&path);

        AuthService {
            instance: route_config::with_change_password_route(self.instance, path),
        }
    }
}

impl<R> AuthService<R>
where
    R: RouteConfig,
    R::Scheme: HttpAuthenticationScheme + SupportsAccountDeletion,
{
    pub fn with_delete_account(
        self,
        path: Option<&str>,
    ) -> AuthService<impl RouteConfig<Scheme = R::Scheme>> {
        let path = path.unwrap_or("/delete-account");

        validate_path(&path);

        AuthService {
            instance: route_config::with_delete_account_route(self.instance, path),
        }
    }
}

impl<R> Into<Router> for AuthService<R>
where
    R: RouteConfig,
{
    fn into(self) -> Router {
        self.instance.build()
    }
}

fn validate_path(path: &str) {
    if path.trim().is_empty() {
        panic!("Route path cannot be empty or whitespace-only");
    }
}
