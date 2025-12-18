use axum::{
    Router,
    http::{HeaderValue, Method, request},
    routing::{delete, post},
};
use tempered_adapters::{
    config::AllowedOrigins,
    http::routes::{
        change_password, delete_account, elevate, login, logout, signup, verify_2fa,
        verify_elevated_token, verify_token,
    },
};
use tempered_core::{BannedTokenStore, EmailClient, TwoFaCodeStore, UserStore};
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
    ///
    /// # Note on Architecture
    /// Stores implement Clone via internal Arc<RwLock> for thread-safe sharing.
    /// Each route is given its specific state requirements, avoiding unnecessary cloning.
    pub fn new<U, B, T, E>(
        user_store: U,
        banned_token_store: B,
        two_fa_code_store: T,
        email_client: E,
        assets_dir: String,
    ) -> Self
    where
        U: UserStore + Clone + 'static,
        B: BannedTokenStore + Clone + 'static,
        T: TwoFaCodeStore + Clone + 'static,
        E: EmailClient + Clone + 'static,
    {
        let assets_service =
            ServeDir::new(assets_dir.clone()).fallback(ServeFile::new(assets_dir + "/index.html"));

        let router = Router::new()
            // Signup only needs user store
            .route("/signup", post(signup::<U>))
            .with_state(user_store.clone())
            // Login needs user store, 2FA store, and email client
            .route("/login", post(login::<U, T, E>))
            .with_state((
                user_store.clone(),
                two_fa_code_store.clone(),
                email_client.clone(),
            ))
            // Logout only needs banned token store
            .route("/logout", post(logout::<B>))
            .with_state(banned_token_store.clone())
            // Verify 2FA only needs 2FA code store
            .route("/verify-2fa", post(verify_2fa::<T>))
            .with_state(two_fa_code_store.clone())
            // Verify token only needs banned token store
            .route("/verify-token", post(verify_token::<B>))
            .with_state(banned_token_store.clone())
            // Verify elevated token only needs banned token store
            .route("/verify-elevated-token", post(verify_elevated_token::<B>))
            .with_state(banned_token_store.clone())
            // Elevate needs user store and banned token store
            .route("/elevate", post(elevate::<U, B>))
            .with_state((user_store.clone(), banned_token_store.clone()))
            // Change password needs user store and banned token store
            .route("/change-password", post(change_password::<U, B>))
            .with_state((user_store.clone(), banned_token_store.clone()))
            // Delete account needs user store and banned token store
            .route("/delete-account", delete(delete_account::<U, B>))
            .with_state((user_store, banned_token_store))
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
    pub fn as_nested_router(mut self, allowed_origins: Option<AllowedOrigins>) -> Router {
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
        let router = self.as_nested_router(allowed_origins);

        tracing::info!("Auth service listening on {}", listener.local_addr()?);

        axum_server::Server::<std::net::SocketAddr>::from_listener(listener)
            .serve(router.into_make_service())
            .await
    }
}
