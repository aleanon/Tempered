use secrecy::Secret;

/// Static configuration for a single OAuth2 / OIDC provider (Google, GitHub, …).
///
/// Pure data — building the authorize URL and performing the token exchange
/// live in the adapter layer so the domain stays free of HTTP dependencies.
#[derive(Clone)]
pub struct OAuthProviderConfig {
    /// Provider key used in routes and identity records, e.g. `"google"`.
    pub name: String,
    pub client_id: String,
    pub client_secret: Secret<String>,
    /// Authorization endpoint the user is redirected to.
    pub auth_url: String,
    /// Token endpoint where the authorization `code` is exchanged.
    pub token_url: String,
    /// Userinfo endpoint queried with the access token.
    pub userinfo_url: String,
    /// Our callback URL registered with the provider.
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

/// The identity returned by a provider's userinfo endpoint.
#[derive(Debug, Clone)]
pub struct OAuthUserInfo {
    /// Stable, provider-unique subject identifier (`sub`).
    pub subject: String,
    pub email: String,
    /// Whether the provider asserts the email is verified (OIDC `email_verified`).
    /// Identity must never be derived from an unverified email.
    pub email_verified: bool,
}

/// An authorization request that has been sent to a provider and is awaiting
/// its callback; held by an [`OAuthStateStore`](crate::OAuthStateStore) under
/// the request's `state`.
#[derive(Clone)]
pub struct PendingAuthorization {
    /// The provider the request was sent to. A callback is only accepted on
    /// that same provider's callback route, so a `state` (and its PKCE
    /// verifier) issued for one provider can never be redeemed at another's
    /// token endpoint.
    pub provider: String,
    /// The PKCE verifier generated for this request (RFC 7636). Secret: it
    /// leaves the server only in the back-channel token request.
    pub code_verifier: Secret<String>,
}
