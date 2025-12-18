use std::sync::{Arc, LazyLock};

use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use chrono::Utc;
use color_eyre::eyre::eyre;
use jsonwebtoken::{DecodingKey, EncodingKey, Validation, decode, encode};
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize, ser::SerializeStruct};
use tempered_core::{BannedTokenStore, Email};
use thiserror::Error;

use crate::config::settings::{AuthServiceSetting, Config};

pub static JWT_COOKIE_NAME: LazyLock<&'static str> = LazyLock::new(|| {
    let cookie_name = AuthServiceSetting::load().auth.jwt.cookie_name.clone();
    Box::leak(cookie_name.into_boxed_str())
});
pub static JWT_ELEVATED_COOKIE_NAME: LazyLock<&'static str> = LazyLock::new(|| {
    let cookie_name = AuthServiceSetting::load()
        .auth
        .elevated_jwt
        .cookie_name
        .clone();
    Box::leak(cookie_name.into_boxed_str())
});

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
    UnexpectedError(#[source] color_eyre::Report),
}

pub fn extract_token<'a>(jar: &'a CookieJar, cookie_name: &str) -> Result<&'a str, TokenAuthError> {
    match jar.get(cookie_name) {
        Some(cookie) => Ok(cookie.value()),
        None => Err(TokenAuthError::MissingToken),
    }
}

// Create cookie with a new JWT auth token
pub fn generate_auth_cookie(
    email: &Email,
    config: &Arc<Config>,
) -> Result<Cookie<'static>, TokenAuthError> {
    let token_ttl = config.auth.jwt.time_to_live;
    let jwt_secret = config.auth.jwt.secret.expose_secret().as_bytes();

    let token = generate_auth_token(email, token_ttl, jwt_secret)?;
    Ok(create_auth_cookie(token, *JWT_COOKIE_NAME))
}

pub fn generate_elevated_auth_cookie(
    email: &Email,
    config: &Arc<Config>,
) -> Result<Cookie<'static>, TokenAuthError> {
    let token_ttl = config.auth.elevated_jwt.time_to_live;
    let jwt_secret = config.auth.elevated_jwt.secret.expose_secret().as_bytes();

    let token = generate_auth_token(email, token_ttl, jwt_secret)?;
    Ok(create_auth_cookie(token, *JWT_ELEVATED_COOKIE_NAME))
}

pub fn create_removal_cookie(cookie_name: &str) -> Cookie<'_> {
    let mut cookie = create_auth_cookie(String::new(), cookie_name);
    cookie.make_removal();
    cookie
}

// Create cookie and set the value to the passed-in token string
pub fn create_auth_cookie(token: String, cookie_name: &str) -> Cookie<'_> {
    Cookie::build((cookie_name, token))
        .path("/") // apply cookie to all URLs on the server
        .http_only(true) // prevent JavaScript from accessing the cookie
        .secure(true)
        .same_site(SameSite::Lax) // send cookie with "same-site" requests, and with "cross-site" top-level navigations.
        .build()
}

// Create JWT auth token
fn generate_auth_token(
    email: &Email,
    token_ttl_seconds: i64,
    secret: &[u8],
) -> Result<String, TokenAuthError> {
    let delta = chrono::Duration::try_seconds(token_ttl_seconds).ok_or(
        TokenAuthError::UnexpectedError(eyre!("Failed to create auth token duration")),
    )?;

    // Create JWT expiration time
    let exp = Utc::now()
        .checked_add_signed(delta)
        .ok_or(TokenAuthError::UnexpectedError(eyre!(
            "Duration out of range",
        )))?
        .timestamp();

    // Cast exp to a usize, which is what Claims expects
    let exp: usize = exp
        .try_into()
        .map_err(|_| TokenAuthError::UnexpectedError(eyre!("Failed to cast i64 to usize")))?;

    let sub = Clone::clone(email.as_ref());

    let claims = Claims { sub, exp };

    create_token(&claims, secret)
}

// Check if JWT auth token is valid by decoding it using the JWT secret
pub async fn validate_auth_token(
    token: &str,
    banned_token_store: &dyn BannedTokenStore,
) -> Result<Claims, TokenAuthError> {
    let config = AuthServiceSetting::load();
    let jwt_secret = config.auth.jwt.secret.expose_secret().as_bytes();
    validate_token(token, banned_token_store, jwt_secret).await
}

pub async fn validate_elevated_auth_token(
    token: &str,
    banned_token_store: &dyn BannedTokenStore,
) -> Result<Claims, TokenAuthError> {
    let config = AuthServiceSetting::load();
    let jwt_secret = config.auth.elevated_jwt.secret.expose_secret().as_bytes();
    validate_token(token, banned_token_store, jwt_secret).await
}

async fn validate_token(
    token: &str,
    banned_token_store: &dyn BannedTokenStore,
    secret: &[u8],
) -> Result<Claims, TokenAuthError> {
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(TokenAuthError::TokenError)?;

    let token = create_token(&claims, secret)?;

    let is_banned = banned_token_store
        .contains_token(&token)
        .await
        .map_err(|e| TokenAuthError::UnexpectedError(eyre!(e)))?;

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

#[derive(Debug, Deserialize)]
pub struct Claims {
    pub sub: Secret<String>,
    pub exp: usize,
}

impl Serialize for Claims {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Claims", 2)?;
        state.serialize_field("sub", &self.sub.expose_secret())?;
        state.serialize_field("exp", &self.exp)?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use secrecy::{ExposeSecret, Secret};

    use crate::persistence::hashset_banned_token_store::HashSetBannedTokenStore;

    use super::*;

    #[tokio::test]
    async fn test_generate_auth_cookie() {
        let config = AuthServiceSetting::load();
        let email = Email::try_from(Secret::from("test@example.com".to_owned())).unwrap();
        let cookie = generate_auth_cookie(&email, &config).unwrap();
        assert_eq!(cookie.name(), config.auth.jwt.cookie_name);
        assert_eq!(cookie.value().split('.').count(), 3);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_create_auth_cookie() {
        let config = AuthServiceSetting::load();
        let jwt_cookie_name = config.auth.jwt.cookie_name.clone();
        let token = "test_token".to_owned();
        let cookie = create_auth_cookie(token.clone(), &jwt_cookie_name);
        assert_eq!(cookie.name(), jwt_cookie_name);
        assert_eq!(cookie.value(), token);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_generate_auth_token() {
        let config = AuthServiceSetting::load();
        let token_ttl = config.auth.jwt.time_to_live;
        let jwt_secret = config.auth.jwt.secret.expose_secret().as_bytes();
        let email = Email::try_from(Secret::from("test@example.com".to_owned())).unwrap();
        let result = generate_auth_token(&email, token_ttl, jwt_secret).unwrap();
        assert_eq!(result.split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_validate_token_with_valid_token() {
        let config = AuthServiceSetting::load();
        let token_ttl = config.auth.jwt.time_to_live;
        let jwt_secret = config.auth.jwt.secret.expose_secret().as_bytes();
        let email = Email::try_from(Secret::from("test@example.com".to_owned())).unwrap();
        let banned_token_store = HashSetBannedTokenStore::default();
        let token = generate_auth_token(&email, token_ttl, jwt_secret).unwrap();
        let result = validate_auth_token(&token, &banned_token_store)
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
        let token = "invalid_token".to_owned();
        let banned_token_store = HashSetBannedTokenStore::default();
        let result = validate_auth_token(&token, &banned_token_store).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_ban_token() {
        let config = AuthServiceSetting::load();
        let token_ttl = config.auth.jwt.time_to_live;
        let jwt_secret = config.auth.jwt.secret.expose_secret().as_bytes();
        let email = Email::try_from(Secret::from("test@example.com".to_owned())).unwrap();
        let banned_token_store = HashSetBannedTokenStore::default();
        let token = generate_auth_token(&email, token_ttl, jwt_secret).unwrap();

        banned_token_store.ban_token(token.clone()).await.unwrap();
        let result = validate_auth_token(&token, &banned_token_store).await;
        assert!(result.is_err());
    }
}
