use async_trait::async_trait;
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Validation, decode, encode};
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize, ser::SerializeStruct};
use tempered_core::{AuthValidator, BannedTokenStore, Email, IntoStatusMessage};
use thiserror::Error;

#[derive(Clone)]
pub struct JwtAuthConfig {
    pub jwt_cookie_name: String,
    pub jwt_secret: Secret<String>,
    pub token_ttl_in_seconds: u64,
    /// When set, issued tokens carry this `aud` claim and validation requires
    /// it — a token signed with the same secret for a *different* audience
    /// (another service or environment) is rejected. `None` disables both.
    pub audience: Option<String>,
    /// When set, issued tokens carry this `iss` claim and validation requires
    /// it. `None` disables both.
    pub issuer: Option<String>,
}

impl JwtAuthConfig {
    pub fn as_bytes(&self) -> &[u8] {
        self.jwt_secret.expose_secret().as_bytes()
    }
}

#[derive(Clone)]
pub struct LocalJwtValidator<B> {
    pub banned_token_store: B,
    pub config: JwtAuthConfig,
}

impl<B> LocalJwtValidator<B> {
    pub fn new(banned_token_store: B, config: JwtAuthConfig) -> Self {
        Self {
            banned_token_store,
            config,
        }
    }
}

#[async_trait]
impl<B: BannedTokenStore + Clone + 'static> AuthValidator for LocalJwtValidator<B> {
    type Claims = Claims;
    type RequestParts = http::request::Parts;
    type Error = TokenAuthError;

    async fn validate(&self, parts: &Self::RequestParts) -> Result<Self::Claims, Self::Error> {
        // Extract cookie jar from request headers
        let cookie_jar = CookieJar::from_headers(&parts.headers);

        // Extract JWT token from cookie
        let token = extract_token(&cookie_jar, &self.config.jwt_cookie_name)?;

        // Validate token signature and check if banned
        let claims = validate_auth_token(token, &self.banned_token_store, &self.config).await?;

        Ok(claims)
    }
}

#[derive(Debug, Error)]
pub enum TokenAuthError {
    #[error("Missing token")]
    MissingToken,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Token error: {0}")]
    TokenError(jsonwebtoken::errors::Error),
    #[error("Token is banned")]
    TokenIsBanned,
    #[error("Unexpected error")]
    UnexpectedError(String),
}

impl IntoStatusMessage for TokenAuthError {
    fn into_status_message(self) -> (http::StatusCode, String) {
        match self {
            TokenAuthError::MissingToken => {
                (http::StatusCode::UNAUTHORIZED, "Missing token".to_string())
            }
            TokenAuthError::InvalidToken => {
                (http::StatusCode::UNAUTHORIZED, "Invalid token".to_string())
            }
            // Don't tell the client *why* the token failed (expired vs. bad
            // signature vs. malformed) — that detail aids forgery analysis.
            TokenAuthError::TokenError(e) => {
                tracing::debug!(error = %e, "token validation failed");
                (http::StatusCode::UNAUTHORIZED, "Invalid token".to_string())
            }
            TokenAuthError::TokenIsBanned => {
                (http::StatusCode::UNAUTHORIZED, "Token is banned".to_string())
            }
            TokenAuthError::UnexpectedError(msg) => {
                tracing::error!(error = %msg, "unexpected token error");
                (
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error".to_string(),
                )
            }
        }
    }
}

pub fn extract_token<'a>(jar: &'a CookieJar, cookie_name: &str) -> Result<&'a str, TokenAuthError> {
    match jar.get(cookie_name) {
        Some(cookie) => {
            let value = cookie.value();
            if value.is_empty() {
                Err(TokenAuthError::MissingToken)
            } else {
                Ok(value)
            }
        }
        None => Err(TokenAuthError::MissingToken),
    }
}

// Create cookie with a new JWT auth token
pub fn generate_auth_cookie<'a>(
    email: &Email,
    config: &'a JwtAuthConfig,
) -> Result<Cookie<'a>, TokenAuthError> {
    let token = generate_auth_token(email, config)?;
    let max_age = time::Duration::seconds(config.token_ttl_in_seconds as i64);
    Ok(create_auth_cookie(
        token,
        &config.jwt_cookie_name,
        Some(max_age),
    ))
}

pub fn create_removal_cookie(cookie_name: &str) -> Cookie<'_> {
    let mut cookie = create_auth_cookie(String::new(), cookie_name, None);
    cookie.make_removal();
    cookie
}

// Create cookie and set the value to the passed-in token string. `max_age`
// bounds the browser-side lifetime to the token's TTL so a persisted cookie
// can't outlive the session it represents; pass `None` for a session cookie.
pub fn create_auth_cookie(
    token: String,
    cookie_name: &str,
    max_age: Option<time::Duration>,
) -> Cookie<'_> {
    let mut builder = Cookie::build((cookie_name, token))
        .path("/") // apply cookie to all URLs on the server
        .http_only(true) // prevent JavaScript from accessing the cookie
        .secure(true)
        .same_site(SameSite::Lax); // send cookie with "same-site" requests, and with "cross-site" top-level navigations.
    if let Some(max_age) = max_age {
        builder = builder.max_age(max_age);
    }
    builder.build()
}

// Create JWT auth token
pub fn generate_auth_token(email: &Email, config: &JwtAuthConfig) -> Result<String, TokenAuthError> {
    let delta = chrono::Duration::try_seconds(config.token_ttl_in_seconds as i64).ok_or(
        TokenAuthError::UnexpectedError("Failed to create auth token duration".to_string()),
    )?;

    // Create JWT expiration time
    let exp = Utc::now()
        .checked_add_signed(delta)
        .ok_or(TokenAuthError::UnexpectedError(
            "Duration out of range".to_string(),
        ))?
        .timestamp();

    // Cast exp to a usize, which is what Claims expects
    let exp: usize = exp
        .try_into()
        .map_err(|_| TokenAuthError::UnexpectedError("Failed to cast i64 to usize".to_string()))?;

    let sub = Clone::clone(email.as_ref());

    let claims = Claims {
        sub,
        exp,
        aud: config.audience.clone(),
        iss: config.issuer.clone(),
    };

    create_token(&claims, config.jwt_secret.expose_secret().as_bytes())
}

// Check if JWT auth token is valid by decoding it using the JWT secret
pub async fn validate_auth_token(
    token: &str,
    banned_token_store: &dyn BannedTokenStore,
    config: &JwtAuthConfig,
) -> Result<Claims, TokenAuthError> {
    let secret = config.jwt_secret.expose_secret().as_bytes();

    // When an audience/issuer is configured, the claim is *required*, not just
    // checked-if-present — otherwise a token minted with the same secret but
    // without the claim (another service or environment) would validate here.
    let mut validation = Validation::default();
    if let Some(aud) = &config.audience {
        validation.set_audience(&[aud]);
        validation.required_spec_claims.insert("aud".to_owned());
    }
    if let Some(iss) = &config.issuer {
        validation.set_issuer(&[iss]);
        validation.required_spec_claims.insert("iss".to_owned());
    }

    let claims = decode::<Claims>(token, &DecodingKey::from_secret(secret), &validation)
        .map(|data| data.claims)
        .map_err(TokenAuthError::TokenError)?;

    // Check the token string as presented. The store holds tokens exactly as
    // issued (logout bans the cookie value), and re-encoding decoded claims
    // would only match if serialization stays byte-for-byte deterministic —
    // any new claim field would silently disarm every existing ban.
    let is_banned = banned_token_store
        .contains_token(token)
        .await
        .map_err(|e| TokenAuthError::UnexpectedError(e.to_string()))?;

    if is_banned {
        return Err(TokenAuthError::TokenIsBanned);
    }

    Ok(claims)
}

// Create JWT auth token by encoding claims using the JWT secret
fn create_token(claims: &Claims, secret: &[u8]) -> Result<String, TokenAuthError> {
    encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .map_err(TokenAuthError::TokenError)
}

#[derive(Debug, Deserialize, Clone)]
pub struct Claims {
    pub sub: Secret<String>,
    pub exp: usize,
    /// Audience binding; present only when the issuing config sets one.
    pub aud: Option<String>,
    /// Issuer binding; present only when the issuing config sets one.
    pub iss: Option<String>,
}

impl Serialize for Claims {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Omit absent aud/iss entirely: `"aud": null` is not the same as no
        // audience to JWT validators.
        let len = 2 + usize::from(self.aud.is_some()) + usize::from(self.iss.is_some());
        let mut state = serializer.serialize_struct("Claims", len)?;
        state.serialize_field("sub", &self.sub.expose_secret())?;
        state.serialize_field("exp", &self.exp)?;
        if let Some(aud) = &self.aud {
            state.serialize_field("aud", aud)?;
        }
        if let Some(iss) = &self.iss {
            state.serialize_field("iss", iss)?;
        }
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use secrecy::{ExposeSecret, Secret};

    use crate::persistence::hashset_banned_token_store::HashSetBannedTokenStore;

    use super::*;

    fn jwt_auth_config() -> JwtAuthConfig {
        JwtAuthConfig {
            token_ttl_in_seconds: 600,
            jwt_cookie_name: "jwt_cookie".to_string(),
            jwt_secret: Secret::from("secret".to_owned()),
            audience: None,
            issuer: None,
        }
    }

    #[tokio::test]
    async fn test_generate_auth_cookie() {
        let config = jwt_auth_config();
        let email = Email::try_from(Secret::from("test@example.com".to_owned())).unwrap();
        let cookie = generate_auth_cookie(&email, &config).unwrap();
        assert_eq!(cookie.name(), config.jwt_cookie_name);
        assert_eq!(cookie.value().split('.').count(), 3);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_create_auth_cookie() {
        let config = jwt_auth_config();
        let jwt_cookie_name = config.jwt_cookie_name.clone();
        let token = "test_token".to_owned();
        let max_age = time::Duration::seconds(3600);
        let cookie = create_auth_cookie(token.clone(), &jwt_cookie_name, Some(max_age));
        assert_eq!(cookie.name(), jwt_cookie_name);
        assert_eq!(cookie.value(), token);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
        assert_eq!(cookie.max_age(), Some(max_age));
    }

    #[tokio::test]
    async fn test_generate_auth_token() {
        let config = jwt_auth_config();
        let email = Email::try_from(Secret::from("test@example.com".to_owned())).unwrap();
        let result = generate_auth_token(&email, &config).unwrap();
        assert_eq!(result.split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_validate_token_with_valid_token() {
        let config = jwt_auth_config();
        let email = Email::try_from(Secret::from("test@example.com".to_owned())).unwrap();
        let banned_token_store = HashSetBannedTokenStore::default();
        let token = generate_auth_token(&email, &config).unwrap();
        let result = validate_auth_token(&token, &banned_token_store, &config)
            .await
            .unwrap();
        assert_eq!(result.sub.expose_secret(), "test@example.com");

        let exp = Utc::now()
            .checked_add_signed(chrono::Duration::try_minutes(9).expect("valid duration"))
            .expect("valid timestamp")
            .timestamp();

        assert!(result.exp > exp as usize);
    }

    #[tokio::test]
    async fn test_validate_token_with_invalid_token() {
        let config = jwt_auth_config();
        let token = "invalid_token".to_owned();
        let banned_token_store = HashSetBannedTokenStore::default();
        let result = validate_auth_token(&token, &banned_token_store, &config).await;
        assert!(result.is_err());
    }

    fn jwt_auth_config_with_aud_iss() -> JwtAuthConfig {
        JwtAuthConfig {
            audience: Some("test-service".to_owned()),
            issuer: Some("test-issuer".to_owned()),
            ..jwt_auth_config()
        }
    }

    #[tokio::test]
    async fn test_validate_token_with_matching_aud_iss() {
        let config = jwt_auth_config_with_aud_iss();
        let email = Email::try_from(Secret::from("test@example.com".to_owned())).unwrap();
        let banned_token_store = HashSetBannedTokenStore::default();
        let token = generate_auth_token(&email, &config).unwrap();
        let claims = validate_auth_token(&token, &banned_token_store, &config)
            .await
            .unwrap();
        assert_eq!(claims.aud.as_deref(), Some("test-service"));
        assert_eq!(claims.iss.as_deref(), Some("test-issuer"));
    }

    #[tokio::test]
    async fn test_validate_token_rejects_wrong_audience() {
        let issuing_config = JwtAuthConfig {
            audience: Some("other-service".to_owned()),
            ..jwt_auth_config_with_aud_iss()
        };
        let validating_config = jwt_auth_config_with_aud_iss();
        let email = Email::try_from(Secret::from("test@example.com".to_owned())).unwrap();
        let banned_token_store = HashSetBannedTokenStore::default();
        let token = generate_auth_token(&email, &issuing_config).unwrap();
        let result = validate_auth_token(&token, &banned_token_store, &validating_config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_token_rejects_missing_aud_when_required() {
        // Token minted without aud/iss (same secret) must not validate against
        // a config that binds them.
        let issuing_config = jwt_auth_config();
        let validating_config = jwt_auth_config_with_aud_iss();
        let email = Email::try_from(Secret::from("test@example.com".to_owned())).unwrap();
        let banned_token_store = HashSetBannedTokenStore::default();
        let token = generate_auth_token(&email, &issuing_config).unwrap();
        let result = validate_auth_token(&token, &banned_token_store, &validating_config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_ban_token() {
        let config = jwt_auth_config();
        let email = Email::try_from(Secret::from("test@example.com".to_owned())).unwrap();
        let banned_token_store = HashSetBannedTokenStore::default();
        let token = generate_auth_token(&email, &config).unwrap();

        banned_token_store.ban_token(token.clone()).await.unwrap();
        let result = validate_auth_token(&token, &banned_token_store, &config).await;
        assert!(result.is_err());
    }
}
