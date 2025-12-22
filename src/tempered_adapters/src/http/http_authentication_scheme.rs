use async_trait::async_trait;
use tempered_core::{AuthenticationScheme, LoginOutcome, SupportsElevation};

use super::http_abstraction::{AuthRequest, AuthResponseBuilder};

/// Framework-agnostic HTTP-level abstraction for authentication schemes.
///
/// This trait uses zero-cost trait abstractions (`AuthRequest`, `AuthResponseBuilder`)
/// making it compatible with any Rust web framework (Axum, Actix, Hyper, etc.).
///
/// Frameworks implement `AuthRequest` and `AuthResponseBuilder` on their own types,
/// and this trait uses those implementations - resulting in zero allocation overhead.
///
/// This trait bridges domain-level authentication (`AuthenticationScheme`)
/// with HTTP-specific concerns like how tokens are delivered to clients.
///
/// Different authentication schemes have different HTTP delivery mechanisms:
/// - JWT: Tokens in HTTP-only cookies
/// - API Keys: Tokens in JSON response body
/// - Bearer Tokens: Tokens in Authorization headers
/// - OAuth2: Redirect URLs with tokens in query params
///
/// By separating these concerns, the domain logic (`AuthenticationScheme`)
/// remains independent of HTTP transport details.
///
/// # Example
///
/// ```ignore
/// // A JWT scheme that delivers tokens via cookies
/// impl HttpAuthenticationScheme for JwtScheme<...> {
///     fn create_login_response(&self, outcome: LoginOutcome<Self::Token>) -> Response {
///         match outcome {
///             LoginOutcome::Success(token) => {
///                 let cookie = Cookie::build("auth", token.as_str())
///                     .http_only(true)
///                     .secure(true)
///                     .build();
///                 // Set cookie and return response
///             }
///             LoginOutcome::Requires2Fa { .. } => {
///                 // Return 2FA required response
///             }
///         }
///     }
/// }
/// ```
#[async_trait]
pub trait HttpAuthenticationScheme: AuthenticationScheme {
    /// Create an HTTP response from a login outcome.
    ///
    /// This method encapsulates how tokens are delivered to the client:
    /// - For cookie-based schemes: Set-Cookie header
    /// - For header-based schemes: Return token in JSON body
    /// - For OAuth2: Redirect response
    ///
    /// The implementation controls:
    /// - Response status code
    /// - Response body format
    /// - Headers (Set-Cookie, etc.)
    /// - How 2FA requirements are communicated
    ///
    /// # Type Parameters
    ///
    /// * `B` - The response builder type (framework-specific)
    ///
    /// # Zero-Cost Abstraction
    ///
    /// This uses generic type parameters, so it compiles to direct calls
    /// with zero runtime overhead. Each framework's response builder is
    /// used directly without any intermediate allocations.
    fn create_login_response<B: AuthResponseBuilder>(
        &self,
        builder: B,
        outcome: LoginOutcome<Self::Token>,
    ) -> B::Response;

    /// Create an HTTP response for logout.
    ///
    /// Different schemes handle logout differently:
    /// - Cookie-based: Clear the cookie with Max-Age=0
    /// - Header-based: Just return success message
    /// - Stateful: Invalidate session on server
    ///
    /// The implementation controls:
    /// - How tokens/cookies are cleared
    /// - Success response format
    ///
    /// # Type Parameters
    ///
    /// * `B` - The response builder type (framework-specific)
    fn create_logout_response<B: AuthResponseBuilder>(
        &self,
        builder: B,
        cookie_name: Option<String>,
    ) -> B::Response;

    /// Create an HTTP response from a 2FA verification outcome.
    ///
    /// Similar to `create_login_response`, but specifically for 2FA completion.
    /// Most schemes will implement this the same as successful login.
    ///
    /// # Type Parameters
    ///
    /// * `B` - The response builder type (framework-specific)
    fn create_2fa_response<B: AuthResponseBuilder>(
        &self,
        builder: B,
        token: Self::Token,
    ) -> B::Response {
        // Default: treat 2FA success same as login success
        self.create_login_response(builder, LoginOutcome::Success(token))
    }

    /// Extract a token from an HTTP request.
    ///
    /// Different schemes extract tokens from different locations:
    /// - Cookie-based (JWT): Read from cookie
    /// - Header-based (API Key): Read from Authorization header
    /// - Session-based: Read session cookie
    ///
    /// This method allows each scheme to define where its tokens live.
    ///
    /// # Type Parameters
    ///
    /// * `R` - The request type (framework-specific)
    ///
    /// # Zero-Cost Abstraction
    ///
    /// The request is passed by reference and the trait methods just
    /// delegate to the framework's existing methods - zero allocations.
    fn extract_token_from_request<R: AuthRequest>(&self, req: &R) -> Option<Self::Token>;
}

/// Extension trait for authentication schemes that support elevated tokens.
///
/// This is separate from `HttpAuthenticationScheme` because not all schemes
/// support elevation (e.g., API keys, OAuth2 providers).
///
/// Only schemes that implement `tempered_core::SupportsElevation` should
/// implement this trait.
pub trait HttpElevationScheme: SupportsElevation {
    /// Create an HTTP response containing an elevated token.
    ///
    /// Similar to `create_login_response`, but for elevated tokens.
    /// These tokens typically:
    /// - Have shorter expiry times (e.g., 5-15 minutes)
    /// - Are stored in separate cookies/headers
    /// - Have different claims/scopes
    ///
    /// # Type Parameters
    ///
    /// * `B` - The response builder type (framework-specific)
    fn create_elevation_response<B: AuthResponseBuilder>(
        &self,
        builder: B,
        elevated_token: Self::ElevatedToken,
    ) -> B::Response;

    /// Extract an elevated token from an HTTP request.
    ///
    /// Elevated tokens are typically stored separately from regular tokens:
    /// - Different cookie name (e.g., `elevated_auth` vs `auth`)
    /// - Different header (e.g., `X-Elevated-Token`)
    ///
    /// # Type Parameters
    ///
    /// * `R` - The request type (framework-specific)
    fn extract_elevated_token_from_request<R: AuthRequest>(
        &self,
        req: &R,
    ) -> Option<Self::ElevatedToken>;
}
