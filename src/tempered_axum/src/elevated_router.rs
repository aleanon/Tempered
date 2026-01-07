use axum::{
    Router,
    routing::{delete, post},
};
use tempered_core::{
    HttpAuthenticationScheme, HttpElevationScheme, SupportsAccountDeletion, SupportsElevation,
    SupportsPasswordChange,
};

/// A builder for configuring elevated routes that require elevated authentication
pub struct ElevatedRouter<S>(pub Router<S>);

impl<S> ElevatedRouter<S>
where
    S: HttpElevationScheme + SupportsElevation + Clone + Send + Sync + 'static,
{
    /// Create a new ElevatedRouter with the specified paths for elevation routes
    pub fn new(verify_elevated_token_path: String) -> Self {
        let mut elevated_router = Router::new();

        // Register verify_elevated_token route
        elevated_router = elevated_router.route(
            &verify_elevated_token_path,
            post(crate::routes::verify_elevated_token::<S>),
        );

        Self(elevated_router)
    }
}

impl<S> ElevatedRouter<S>
where
    S: HttpAuthenticationScheme + SupportsPasswordChange,
{
    /// Add the change password route to the elevated router
    pub fn with_change_password(mut self, path: Option<&str>) -> Self {
        let path = path.unwrap_or("/change-password");

        self.0 = self
            .0
            .route(path, post(crate::routes::change_password::<S>));

        self
    }
}

impl<S> ElevatedRouter<S>
where
    S: HttpAuthenticationScheme + SupportsAccountDeletion,
{
    /// Add the delete account route to the elevated router
    pub fn with_delete_account(mut self, path: Option<&str>) -> Self {
        let path = path.unwrap_or("/delete-account");

        self.0 = self
            .0
            .route(path, delete(crate::routes::delete_account::<S>));

        self
    }
}
