use async_trait::async_trait;

/// Trait for validating authentication tokens in middleware.
///
/// Validators extract authentication information from HTTP requests,
/// verify tokens/sessions, and produce claims/session data for protected routes.
///
/// Different authentication schemes validate tokens from different locations:
/// - JWT: Extracts from cookies, validates signature
/// - API keys: Extracts from Authorization header, validates against database
/// - OAuth2: Extracts bearer token from header, validates with provider
///
/// # Implementation Note
///
/// The validator receives `RequestParts` (headers, method, URI, extensions) rather
/// than the full `Request` to avoid issues with non-`Sync` request bodies.
/// This is sufficient since validators only need headers to extract tokens.
#[async_trait]
pub trait AuthValidator: Clone + Send + Sync + 'static {
    /// The claims/session data extracted from a valid authentication token.
    ///
    /// This will be made available to protected route handlers via extractors.
    /// Examples:
    /// - JWT: Claims with user email, expiration, roles
    /// - API key: Key ID, user ID, scopes/permissions
    /// - Session: Session ID, user data
    type Claims: Clone + Send + Sync + 'static;

    /// The request parts type this validator operates on.
    ///
    /// Typically `http::request::Parts` containing headers, method, URI, etc.
    type RequestParts;

    /// Errors that can occur during validation.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Validate authentication from the request parts.
    ///
    /// This method:
    /// 1. Extracts the token/credentials from request parts (cookie, header, etc.)
    /// 2. Validates the token (signature, expiration, database lookup, etc.)
    /// 3. Returns the claims/session data to be used by the route handler
    ///
    /// Request parts include headers, method, URI, and extensions - everything
    /// except the request body. This is sufficient for token extraction and avoids
    /// issues with non-`Sync` body types.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No authentication token is present
    /// - The token is invalid or expired
    /// - The token has been revoked
    /// - Database/external validation fails
    async fn validate(&self, parts: &Self::RequestParts) -> Result<Self::Claims, Self::Error>;
}
