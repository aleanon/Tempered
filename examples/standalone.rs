use redis::Client;
use reqwest::Client as HttpClient;
use secrecy::ExposeSecret;
use sqlx::postgres::PgPoolOptions;
use std::{sync::Arc, time::Duration};
use tempered::{
    Email, EmailClient, HashMapTwoFaCodeStore, HashMapUserStore, HashSetBannedTokenStore,
    JwtAuthConfig, JwtScheme, MockEmailClient, PostgresUserStore, PostmarkEmailClient,
    RedisBannedTokenStore, RedisTwoFaCodeStore, Secret, async_trait,
};
use tempered_axum::auth_service::auth_service;
use tokio::sync::RwLock;
use tracing_error::ErrorLayer;
use tracing_subscriber::{
    EnvFilter, filter::ParseError, fmt, layer::SubscriberExt, util::SubscriberInitExt,
};

/// Example of using auth-service-lib to create a standalone auth service
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing().expect("Failed to initialize tracing");

    // Create stores
    let user_store = HashMapUserStore::new();
    let two_fa_code_store = HashMapTwoFaCodeStore::new();

    let email_client = DummyEmailClient;

    // Create JWT configuration for the scheme
    let jwt_config = JwtAuthConfig {
        jwt_cookie_name: "jwt".to_string(),
        jwt_secret: Secret::new("input a long random generated string here".to_string()),
        token_ttl_in_seconds: 3600,
    };

    let elevated_jwt_config = JwtAuthConfig {
        jwt_cookie_name: "elevated_jwt".to_string(),
        jwt_secret: Secret::new("Input a long random generated string here".to_string()),
        token_ttl_in_seconds: 900, // 15 minutes for elevated tokens
    };

    let banned_token_store = HashSetBannedTokenStore::new();
    let elevated_banned_token_store = HashSetBannedTokenStore::new();

    // Create the JwtScheme with all required stores
    let jwt_scheme = JwtScheme::new(
        user_store,
        two_fa_code_store,
        email_client,
        banned_token_store,
        jwt_config,
        elevated_banned_token_store,
        elevated_jwt_config,
    );

    // Create the auth service using the library
    let auth_service = auth_service(jwt_scheme, "examples/assets".to_string())
        .login_route("/login")
        .logout_route("/logout")
        .verify_token_route("/verify-token")
        .signup_route(Some("/signup"))
        .with_2fa(Some("/verify-2fa"))
        .with_elevation(
            Some("/elevate"),
            Some("/verify-elevated-token"),
            |elevated| {
                elevated
                    .with_change_password(Some("/change-password"))
                    .with_delete_account(Some("/delete-account"))
            },
        );

    // Run as standalone server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;

    auth_service.run(listener).await?;

    Ok(())
}

pub fn init_tracing() -> Result<(), ParseError> {
    let fmt_layer = fmt::layer().compact();

    let filter_layer = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new("info"))?;

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .with(ErrorLayer::default())
        .init();

    Ok(())
}

#[derive(Clone)]
struct DummyEmailClient;

#[async_trait]
impl EmailClient for DummyEmailClient {
    async fn send_email(
        &self,
        recipient: &Email,
        subject: &str,
        content: &str,
    ) -> Result<(), String> {
        println!(
            "recipient:{}, subject:{}, content:{}",
            recipient.as_ref().expose_secret(),
            subject,
            content
        );
        Ok(())
    }
}
