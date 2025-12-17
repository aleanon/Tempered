use auth::{
    AuthService, Email, ExposeSecret, PostgresUserStore, PostmarkEmailClient,
    RedisBannedTokenStore, RedisTwoFaCodeStore, Secret, adapters::config::AuthServiceSetting,
};
use color_eyre::eyre::Result;
use redis::Client;
use reqwest::Client as HttpClient;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing_error::ErrorLayer;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// Example of using auth-service-lib to create a standalone auth service
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    color_eyre::install().expect("Failed to install color_eyre");
    init_tracing().expect("Failed to initialize tracing");

    // Load configuration
    let config = AuthServiceSetting::load();

    // Setup database connection pool
    let pg_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(config.postgres.url.expose_secret())
        .await?;

    // Run migrations
    sqlx::migrate!().run(&pg_pool).await?;

    // Setup Redis connection
    let redis_client = Client::open(format!("redis://{}/", config.redis.host_name))?;
    let redis_conn = Arc::new(RwLock::new(redis_client.get_connection()?));

    // Create stores
    let user_store = PostgresUserStore::new(pg_pool);
    let banned_token_store =
        RedisBannedTokenStore::new(redis_conn.clone(), config.auth.jwt.time_to_live as u64);
    let two_fa_code_store = RedisTwoFaCodeStore::new(redis_conn);

    // Create email client
    let http_client = HttpClient::builder()
        .timeout(config.email_client.timeout_in_millis)
        .build()?;

    let email_client = PostmarkEmailClient::new(
        config.email_client.base_url.clone(),
        Email::try_from(Secret::new(config.email_client.sender.clone()))?,
        config.email_client.auth_token.clone(),
        http_client,
    );

    // Create the auth service using the library
    let auth_service = AuthService::new(
        user_store,
        banned_token_store,
        two_fa_code_store,
        email_client,
        "assets".to_string(),
    );

    // Get allowed origins from config
    let allowed_origins = config.auth.allowed_origins.clone();

    // Run as standalone server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    tracing::info!("Starting auth service with auth-service-lib...");

    auth_service
        .run_standalone(listener, Some(allowed_origins))
        .await?;

    Ok(())
}

pub fn init_tracing() -> Result<()> {
    let fmt_layer = fmt::layer().compact();

    let filter_layer = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new("info"))?;

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .with(ErrorLayer::default())
        .init();

    Ok(())
}
