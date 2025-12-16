use auth_adapters::{
    config::AuthServiceSetting,
    email::PostmarkEmailClient,
    http::routes::{
        change_password, delete_account, elevate, login, logout, signup, verify_2fa, verify_token,
    },
    persistence::{PostgresUserStore, RedisBannedTokenStore, RedisTwoFaCodeStore},
};
use auth_core::Email;
use axum::{
    Router,
    routing::{delete, post},
};
use redis::Client;
use reqwest::Client as HttpClient;
use secrecy::ExposeSecret;
use secrecy::Secret;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    color_eyre::install().expect("Failed to install color_eyre");
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Load configuration
    dotenvy::dotenv().ok();
    let config = AuthServiceSetting::load();

    // Setup database connection pool
    let pg_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(config.postgres.url.expose_secret())
        .await?;

    // Run migrations
    sqlx::migrate!("../auth-service-bin/migrations")
        .run(&pg_pool)
        .await?;

    // Setup Redis connection
    let redis_client = Client::open(format!("redis://{}/", config.redis.host_name))?;
    let redis_conn = Arc::new(Mutex::new(redis_client.get_connection()?));

    // Create stores
    let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));
    let banned_token_store = Arc::new(RwLock::new(RedisBannedTokenStore::new(
        redis_conn.clone(),
        config.auth.jwt.time_to_live as u64,
    )));
    let two_fa_code_store = Arc::new(RwLock::new(RedisTwoFaCodeStore::new(redis_conn)));

    // Create email client
    let http_client = HttpClient::builder()
        .timeout(config.email_client.timeout_in_millis)
        .build()?;

    let email_client = Arc::new(PostmarkEmailClient::new(
        config.email_client.base_url.clone(),
        Email::try_from(Secret::new(config.email_client.sender.clone()))?,
        config.email_client.auth_token.clone(),
        http_client,
    ));

    // Build router
    let app = Router::new()
        .route("/signup", post(signup))
        .with_state(user_store.clone())
        .route("/login", post(login))
        .with_state((
            user_store.clone(),
            two_fa_code_store.clone(),
            email_client.clone(),
        ))
        .route("/logout", post(logout))
        .with_state(banned_token_store.clone())
        .route("/verify-2fa", post(verify_2fa))
        .with_state(two_fa_code_store.clone())
        .route("/verify-token", post(verify_token))
        .with_state(banned_token_store.clone())
        .route("/elevate", post(elevate))
        .with_state((user_store.clone(), banned_token_store.clone()))
        .route("/change-password", post(change_password))
        .with_state((user_store.clone(), banned_token_store.clone()))
        .route("/delete-account", delete(delete_account))
        .with_state((user_store, banned_token_store));

    // Start server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    tracing::info!("Listening on {}", listener.local_addr()?);

    axum::serve(listener, app).await?;

    Ok(())
}
