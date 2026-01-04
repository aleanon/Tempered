use axum::{
    Router,
    http::{HeaderValue, Method, request},
    middleware,
    routing::{delete, post},
};
use tempered_adapters::config::AllowedOrigins;
use tempered_axum::routes::{
    change_password, delete_account, elevate, login, logout, signup, verify_2fa,
    verify_elevated_token, verify_token,
};
use tempered_core::{
    AuthValidator, HttpAuthenticationScheme, HttpElevationScheme, IntoStatusMessage,
    SupportsElevation, SupportsRegistration, SupportsTokenRevocation, SupportsTwoFactor,
};
use tokio::net::TcpListener;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};

use crate::tracing::{make_span_with_request_id, on_request, on_response};

/// Main authentication service that provides all auth-related routes
pub struct AuthService {
    router: Router,
}

impl AuthService {
    /// Create a new AuthService with the provided stores and email client
    ///
    /// # Arguments
    /// * `user_store` - Store for user data (must be Clone)
    /// * `banned_token_store` - Store for banned JWT tokens (must be Clone)
    /// * `two_fa_code_store` - Store for 2FA codes (must be Clone)
    /// * `email_client` - Client for sending emails (must be Clone)
    /// * `assets_dir` - Directory for static assets
    ///
    /// # Note on Architecture
    /// This creates a JwtScheme that wraps all the stores and implements
    /// the authentication logic. Routes receive the scheme as state instead
    /// of individual stores.
    pub fn new<A>(auth_schema: A, assets_dir: String) -> Self
    where
        A: HttpAuthenticationScheme
            + HttpElevationScheme
            + SupportsRegistration
            + SupportsElevation
            + SupportsTokenRevocation
            + SupportsTwoFactor
            + tempered_core::SupportsPasswordChange
            + tempered_core::SupportsAccountDeletion
            + Send
            + Sync
            + Clone
            + 'static,
        A::Validator: tempered_core::AuthValidator<RequestParts = http::request::Parts>,
        <A::Validator as AuthValidator>::Error: IntoStatusMessage,
        A::ElevatedValidator: tempered_core::AuthValidator<RequestParts = http::request::Parts>,
        <A::ElevatedValidator as AuthValidator>::Error: IntoStatusMessage,
        A::AuthError: IntoStatusMessage,
        A::RegistrationError: IntoStatusMessage,
        A::TwoFactorError: IntoStatusMessage,
    {
        // Load JWT configuration
        // let config = AuthServiceSetting::load();

        // let jwt_config = JwtAuthConfig {
        //     jwt_cookie_name: config.auth.jwt.cookie_name.clone(),
        //     jwt_secret: config.auth.jwt.secret.clone(),
        //     token_ttl_in_seconds: config.auth.jwt.time_to_live,
        // };

        // let elevated_jwt_config = JwtAuthConfig {
        //     jwt_cookie_name: config.auth.elevated_jwt.cookie_name.clone(),
        //     jwt_secret: config.auth.elevated_jwt.secret.clone(),
        //     token_ttl_in_seconds: config.auth.elevated_jwt.time_to_live,
        // };

        // Create JWT authentication scheme
        // let jwt_scheme = JwtScheme::new(
        //     user_store.clone(),
        //     two_fa_code_store.clone(),
        //     email_client.clone(),
        //     banned_token_store.clone(),
        //     jwt_config,
        //     banned_token_store.clone(),
        //     elevated_jwt_config,
        // );

        let assets_service =
            ServeDir::new(assets_dir.clone()).fallback(ServeFile::new(assets_dir + "/index.html"));

        // Routes that require elevated authentication
        let elevated_routes = Router::new()
            .route("/change-password", post(change_password::<A>))
            .route("/delete-account", delete(delete_account::<A>))
            .route("/verify-elevated-token", post(verify_elevated_token::<A>))
            .layer(middleware::from_fn_with_state(
                auth_schema.clone(),
                tempered_axum::middleware::validate_elevated_token::<A>,
            ));

        let validated_routes = Router::new()
            .route("/logout", post(logout::<A>))
            .route("/elevate", post(elevate::<A>))
            .route("/verify-token", post(verify_token::<A>))
            .layer(middleware::from_fn_with_state(
                auth_schema.clone(),
                tempered_axum::middleware::validate_token::<A>,
            ));

        // All routes use the authentication scheme as state
        let router = Router::new()
            .route("/signup", post(signup::<A>))
            .route("/login", post(login::<A>))
            .route("/verify-2fa", post(verify_2fa::<A>))
            .merge(validated_routes)
            .merge(elevated_routes)
            .with_state(auth_schema)
            .fallback_service(assets_service);

        Self { router }
    }

    fn with_trace_layer(mut self) -> Self {
        self.router = self.router.layer(
            TraceLayer::new_for_http()
                .make_span_with(make_span_with_request_id)
                .on_request(on_request)
                .on_response(on_response),
        );
        self
    }

    /// Convert the AuthService into a nested router that can be mounted on another router
    ///
    /// # Arguments
    /// * `allowed_origins` - Optional list of allowed CORS origins
    ///
    /// # Returns
    /// An Axum Router that can be nested into another application
    pub fn into_router(mut self, allowed_origins: Option<AllowedOrigins>) -> Router {
        if let Some(allowed_origins) = allowed_origins {
            let cors = CorsLayer::new()
                .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
                .allow_credentials(true)
                .allow_origin(AllowOrigin::predicate(
                    move |origin: &HeaderValue, _request_parts: &request::Parts| {
                        allowed_origins.contains(origin)
                    },
                ));

            self.router = self.router.layer(cors);
        }
        self.with_trace_layer().router
    }

    /// Run the auth service as a standalone server
    ///
    /// # Arguments
    /// * `listener` - TCP listener to bind the server to
    /// * `allowed_origins` - Optional list of allowed CORS origins
    ///
    /// # Returns
    /// Result indicating success or error
    pub async fn run_standalone(
        self,
        listener: TcpListener,
        allowed_origins: Option<AllowedOrigins>,
    ) -> Result<(), std::io::Error> {
        let router = self.into_router(allowed_origins);

        tracing::info!("Auth service listening on {}", listener.local_addr()?);

        axum_server::Server::<std::net::SocketAddr>::from_listener(listener)
            .serve(router.into_make_service())
            .await
    }
}
