//! Ready-made provider settings, and OIDC discovery for the rest.
//!
//! Each preset takes your client id, client secret and redirect URI (as
//! registered with the provider) and fills in the endpoints and scopes.
//!
//! Apple is not here yet: it sends the address only when the login uses
//! `response_mode=form_post`, a cross-site POST to the callback, and the
//! state cookie (`SameSite=Lax`) is not sent on one.

use secrecy::Secret;
use serde::Deserialize;
use tempered_core::{OAuthHttpClient, OAuthHttpError, OAuthProviderConfig, OidcSettings};

/// Google (OIDC). Registered as provider `"google"`.
pub fn google(
    client_id: impl Into<String>,
    client_secret: Secret<String>,
    redirect_uri: impl Into<String>,
) -> OAuthProviderConfig {
    OAuthProviderConfig {
        name: "google".to_string(),
        client_id: client_id.into(),
        client_secret,
        auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
        token_url: "https://oauth2.googleapis.com/token".to_string(),
        userinfo_url: "https://openidconnect.googleapis.com/v1/userinfo".to_string(),
        redirect_uri: redirect_uri.into(),
        scopes: scopes(&["openid", "email", "profile"]),
        oidc: Some(OidcSettings {
            issuer: "https://accounts.google.com".to_string(),
            jwks_uri: "https://www.googleapis.com/oauth2/v3/certs".to_string(),
        }),
        emails_url: None,
    }
}

/// The tenant id of personal Microsoft accounts (outlook.com, hotmail.com).
pub const MICROSOFT_CONSUMERS_TENANT: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";

/// Microsoft Entra ID / Microsoft accounts (OIDC) for one tenant: your
/// organisation's tenant id, or [`MICROSOFT_CONSUMERS_TENANT`]. Registered
/// as provider `"microsoft"`.
///
/// Microsoft's ID tokens do not say whether the address is verified, so a
/// first login cannot link to an existing account by address (the flow
/// refuses it, which is what stops the "nOAuth" takeover); a login linked
/// once keeps working.
///
/// # Panics
///
/// For the multi-tenant names `common` and `organizations`: their tokens
/// come from each user's own tenant, with an issuer that cannot be checked
/// against a fixed value.
pub fn microsoft(
    tenant: &str,
    client_id: impl Into<String>,
    client_secret: Secret<String>,
    redirect_uri: impl Into<String>,
) -> OAuthProviderConfig {
    assert!(
        !matches!(tenant, "common" | "organizations"),
        "use a tenant id for Microsoft (or MICROSOFT_CONSUMERS_TENANT), not {tenant:?}"
    );
    let base = format!("https://login.microsoftonline.com/{tenant}");
    OAuthProviderConfig {
        name: "microsoft".to_string(),
        client_id: client_id.into(),
        client_secret,
        auth_url: format!("{base}/oauth2/v2.0/authorize"),
        token_url: format!("{base}/oauth2/v2.0/token"),
        userinfo_url: "https://graph.microsoft.com/oidc/userinfo".to_string(),
        redirect_uri: redirect_uri.into(),
        scopes: scopes(&["openid", "email", "profile"]),
        oidc: Some(OidcSettings {
            issuer: format!("{base}/v2.0"),
            jwks_uri: format!("{base}/discovery/v2.0/keys"),
        }),
        emails_url: None,
    }
}

/// GitHub (OAuth2, not OIDC). The address is the account's primary one
/// from `/user/emails`, with GitHub's verified flag. Registered as provider
/// `"github"`.
pub fn github(
    client_id: impl Into<String>,
    client_secret: Secret<String>,
    redirect_uri: impl Into<String>,
) -> OAuthProviderConfig {
    OAuthProviderConfig {
        name: "github".to_string(),
        client_id: client_id.into(),
        client_secret,
        auth_url: "https://github.com/login/oauth/authorize".to_string(),
        token_url: "https://github.com/login/oauth/access_token".to_string(),
        userinfo_url: "https://api.github.com/user".to_string(),
        redirect_uri: redirect_uri.into(),
        scopes: scopes(&["read:user", "user:email"]),
        oidc: None,
        emails_url: Some("https://api.github.com/user/emails".to_string()),
    }
}

/// The parts of an OIDC discovery document the flow uses.
#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: Option<String>,
    jwks_uri: String,
}

/// Settings for any OIDC provider, read from
/// `{issuer}/.well-known/openid-configuration`, registered as provider
/// `name` with the scopes `openid email profile`.
///
/// The document must name `issuer` exactly (OIDC Discovery §4.3), so a
/// document served from the wrong place cannot redirect the login, and it
/// must list a userinfo endpoint.
pub async fn discover(
    http: &impl OAuthHttpClient,
    name: impl Into<String>,
    issuer: &str,
    client_id: impl Into<String>,
    client_secret: Secret<String>,
    redirect_uri: impl Into<String>,
) -> Result<OAuthProviderConfig, OAuthHttpError> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let document: Discovery = serde_json::from_value(http.fetch_json(&url).await?)
        .map_err(|e| OAuthHttpError::Fetch(format!("discovery document: {e}")))?;
    if document.issuer != issuer {
        return Err(OAuthHttpError::Fetch(format!(
            "discovery document is for {:?}, not {issuer:?}",
            document.issuer
        )));
    }
    let userinfo_url = document.userinfo_endpoint.ok_or_else(|| {
        OAuthHttpError::Fetch("discovery document has no userinfo endpoint".into())
    })?;
    Ok(OAuthProviderConfig {
        name: name.into(),
        client_id: client_id.into(),
        client_secret,
        auth_url: document.authorization_endpoint,
        token_url: document.token_endpoint,
        userinfo_url,
        redirect_uri: redirect_uri.into(),
        scopes: scopes(&["openid", "email", "profile"]),
        oidc: Some(OidcSettings {
            issuer: document.issuer,
            jwks_uri: document.jwks_uri,
        }),
        emails_url: None,
    })
}

fn scopes(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use tempered_core::{OAuthUserInfo, TokenResponse};

    struct Serves(serde_json::Value);

    #[async_trait]
    impl OAuthHttpClient for Serves {
        async fn exchange_code(
            &self,
            _: &OAuthProviderConfig,
            _: &str,
            _: &str,
        ) -> Result<TokenResponse, OAuthHttpError> {
            unreachable!()
        }
        async fn fetch_user_info(
            &self,
            _: &OAuthProviderConfig,
            _: &str,
        ) -> Result<OAuthUserInfo, OAuthHttpError> {
            unreachable!()
        }
        async fn fetch_json(&self, url: &str) -> Result<serde_json::Value, OAuthHttpError> {
            assert_eq!(
                url,
                "https://id.example.com/.well-known/openid-configuration"
            );
            Ok(self.0.clone())
        }
    }

    fn document(issuer: &str) -> serde_json::Value {
        serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": "https://id.example.com/authorize",
            "token_endpoint": "https://id.example.com/token",
            "userinfo_endpoint": "https://id.example.com/userinfo",
            "jwks_uri": "https://id.example.com/keys",
        })
    }

    #[tokio::test]
    async fn discovery_fills_in_the_endpoints() {
        let http = Serves(document("https://id.example.com"));
        let config = discover(
            &http,
            "id",
            "https://id.example.com",
            "c",
            Secret::new("s".into()),
            "https://app/cb",
        )
        .await
        .unwrap();
        assert_eq!(config.token_url, "https://id.example.com/token");
        assert_eq!(config.oidc.unwrap().jwks_uri, "https://id.example.com/keys");
    }

    #[tokio::test]
    async fn a_document_for_another_issuer_is_refused() {
        let http = Serves(document("https://evil.example.com"));
        let result = discover(
            &http,
            "id",
            "https://id.example.com",
            "c",
            Secret::new("s".into()),
            "https://app/cb",
        )
        .await;
        assert!(result.is_err());
    }

    #[test]
    fn the_presets_register_with_a_flow() {
        // `with_provider` checks every endpoint and the OIDC scope.
        let secret = || Secret::new("s".to_string());
        let flow = crate::oauth::OAuthFlow::new(
            crate::persistence::HashMapOAuthStateStore::new(),
            crate::persistence::HashMapOAuthIdentityStore::new(),
            Serves(serde_json::Value::Null),
        )
        .with_provider(google("c", secret(), "https://app.example.com/cb"))
        .with_provider(microsoft(
            MICROSOFT_CONSUMERS_TENANT,
            "c",
            secret(),
            "https://app.example.com/cb",
        ))
        .with_provider(github("c", secret(), "https://app.example.com/cb"));
        drop(flow);
    }

    #[test]
    #[should_panic(expected = "use a tenant id")]
    fn the_multi_tenant_microsoft_names_are_refused() {
        microsoft(
            "common",
            "c",
            Secret::new("s".to_string()),
            "https://app/cb",
        );
    }
}
