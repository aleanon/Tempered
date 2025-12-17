use std::{
    ops::Deref,
    sync::{Arc, LazyLock},
    time::Duration,
};

use arc_swap::{ArcSwap, Guard};
use axum::http::HeaderValue;
use color_eyre::eyre::Result;
use config::ConfigError;
use dashmap::DashSet;
use dotenvy::dotenv;
use secrecy::Secret;
use serde::{Deserialize, Deserializer, Serialize};

pub static CONFIG: LazyLock<ArcSwap<Config>> =
    LazyLock::new(|| ArcSwap::from_pointee(Config::new().expect("Failed to load config")));

// Environment variable names
const JWT_SECRET_ENV_VAR: &str = "JWT_SECRET";
const JWT_ELEVATED_SECRET_ENV_VAR: &str = "JWT_ELEVATED_SECRET";
const AUTH_SERVICE_ALLOWED_ORIGINS_ENV_VAR: &str = "AUTH_SERVICE_ALLOWED_ORIGINS";
const DATABASE_URL_ENV_VAR: &str = "DATABASE_URL";
const REDIS_HOST_NAME_ENV_VAR: &str = "REDIS_HOST_NAME";
const POSTMARK_AUTH_TOKEN_ENV_VAR: &str = "POSTMARK_AUTH_TOKEN";

#[derive(Debug)]
#[allow(unused)]
pub struct JWTConfig {
    pub cookie_name: String,
    pub secret: Secret<String>,
    pub time_to_live: i64,
}

impl<'de> Deserialize<'de> for JWTConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            cookie_name: String,
            secret: Secret<String>,
            time_to_live_in_seconds: u64,
        }

        let helper = Helper::deserialize(deserializer)?;
        Ok(Self {
            cookie_name: helper.cookie_name,
            secret: helper.secret,
            time_to_live: helper.time_to_live_in_seconds as i64,
        })
    }
}

#[derive(Debug, Deserialize)]
#[allow(unused)]
pub struct AuthConfig {
    pub jwt: JWTConfig,
    pub elevated_jwt: JWTConfig,
    pub allowed_origins: AllowedOrigins,
}

#[derive(Debug)]
#[allow(unused)]
pub struct EmailClientConfig {
    pub base_url: String,
    pub sender: String,
    pub timeout_in_millis: Duration,
    pub auth_token: Secret<String>,
}

impl<'de> Deserialize<'de> for EmailClientConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            base_url: String,
            sender: String,
            timeout_in_millis: u64,
            auth_token: Secret<String>,
        }

        let helper = Helper::deserialize(deserializer)?;

        let config = EmailClientConfig {
            base_url: helper.base_url,
            sender: helper.sender,
            timeout_in_millis: Duration::from_millis(helper.timeout_in_millis),
            auth_token: helper.auth_token,
        };

        Ok(config)
    }
}

#[derive(Debug, Deserialize)]
#[allow(unused)]
#[serde(default)]
pub struct PostgresConfig {
    pub url: Secret<String>,
    pub max_connections: u32,
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self {
            url: Secret::new("postgres://postgres:postgres@localhost:5432/postgres".to_string()),
            max_connections: 5,
        }
    }
}

#[derive(Debug, Deserialize)]
#[allow(unused)]
pub struct RedisConfig {
    pub host_name: String,
}

#[derive(Debug, Deserialize)]
#[allow(unused)]
pub struct Config {
    pub auth: AuthConfig,
    pub email_client: EmailClientConfig,
    pub postgres: PostgresConfig,
    pub redis: RedisConfig,
}

impl Config {
    pub fn new() -> Result<Self, ConfigError> {
        config::Config::builder()
            .add_source(config::File::with_name("config/config"))
            .add_source(config::Environment::default())
            .set_override("auth.jwt.secret", get_jwt_secret())?
            .set_override("auth.elevated_jwt.secret", get_elevated_jwt_secret())?
            .set_override("email_client.auth_token", get_email_client_auth_token())?
            .set_override("postgres.url", get_database_url())?
            .set_override_option("redis.host_name", get_redis_host_name())?
            .set_override_option("auth.allowed_origins", get_allowed_origins())?
            .build()?
            .try_deserialize()
    }
}

fn get_jwt_secret() -> String {
    dotenv().ok(); // Load environment variables
    let secret = std::env::var(JWT_SECRET_ENV_VAR).expect("JWT_SECRET must be set.");
    if secret.is_empty() {
        panic!("JWT_SECRET must not be empty.");
    }
    secret
}

fn get_elevated_jwt_secret() -> String {
    dotenv().ok();
    let secret =
        std::env::var(JWT_ELEVATED_SECRET_ENV_VAR).expect("JWT_ELEVATED_SECRET must be set.");
    if secret.is_empty() {
        panic!("JWT_ELEVATED_SECRET must not be empty.");
    }
    secret
}

fn get_database_url() -> String {
    dotenv().ok();
    let url = std::env::var(DATABASE_URL_ENV_VAR).expect("DATABASE_URL must be set");
    if url.is_empty() {
        panic!("DATABASE_URL must not be empty.");
    }
    url
}

fn get_redis_host_name() -> Option<String> {
    dotenv().ok();
    std::env::var(REDIS_HOST_NAME_ENV_VAR).ok()
}

fn get_email_client_auth_token() -> String {
    dotenv().ok();
    let token =
        std::env::var(POSTMARK_AUTH_TOKEN_ENV_VAR).expect("POSTMARK_AUTH_TOKEN must be set.");
    if token.is_empty() {
        panic!("POSTMARK_AUTH_TOKEN must not be empty.");
    }
    token
}

fn get_allowed_origins() -> Option<Vec<String>> {
    std::env::var(AUTH_SERVICE_ALLOWED_ORIGINS_ENV_VAR)
        .ok()
        .and_then(|s| {
            Some(
                s.split(',')
                    .map(|origin| origin.trim().to_owned())
                    .collect(),
            )
        })
}

#[derive(Debug, Clone)]
pub struct AuthServiceSetting;

impl AuthServiceSetting {
    pub fn load() -> Guard<Arc<Config>> {
        CONFIG.load()
    }

    pub fn get_config() -> Guard<Arc<Config>> {
        CONFIG.load()
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn test_settings_creation() {
        dotenv().ok();
        let config = AuthServiceSetting::load();
        assert!(!config.auth.jwt.secret.expose_secret().is_empty());
        assert!(!config.auth.elevated_jwt.secret.expose_secret().is_empty());
        assert!(!config.postgres.url.expose_secret().is_empty());
        assert!(!config.email_client.auth_token.expose_secret().is_empty());
    }
}

#[derive(Debug, Clone)]
pub struct AllowedOrigins(Arc<DashSet<HeaderValue>>);

impl AllowedOrigins {
    pub fn new(headers: DashSet<HeaderValue>) -> Self {
        AllowedOrigins(Arc::new(headers))
    }
}

impl Serialize for AllowedOrigins {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let headers = self
            .iter()
            .filter_map(|header_value| header_value.to_str().and_then(|h| Ok(h.to_owned())).ok())
            .collect::<Vec<_>>();

        headers.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AllowedOrigins {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let headers = Vec::<String>::deserialize(deserializer)?
            .iter()
            .filter_map(|value| value.parse().ok())
            .collect();

        Ok(AllowedOrigins::new(headers))
    }
}

impl Deref for AllowedOrigins {
    type Target = Arc<DashSet<HeaderValue>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
