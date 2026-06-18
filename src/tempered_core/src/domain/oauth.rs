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
}
