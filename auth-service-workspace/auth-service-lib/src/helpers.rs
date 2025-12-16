use auth_adapters::config::AuthServiceSetting;
use redis::{Client, RedisResult};
use secrecy::ExposeSecret;
use sqlx::{PgPool, postgres::PgPoolOptions};

/// Configure and return a PostgreSQL connection pool
///
/// This function loads the database URL from configuration, creates a connection pool,
/// and runs all pending migrations.
///
/// # Returns
/// A configured PgPool ready for use
///
/// # Panics
/// Panics if unable to create the pool or run migrations
pub async fn configure_postgresql() -> PgPool {
    let config = AuthServiceSetting::load();
    let db_url = config.postgres.url.expose_secret();

    let pg_pool = get_postgres_pool(db_url)
        .await
        .expect("Failed to create Postgres connection pool");

    // Run database migrations
    sqlx::migrate!("../auth-service-bin/migrations")
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}

/// Configure and return a Redis connection
///
/// This function loads the Redis hostname from configuration and establishes a connection.
///
/// # Returns
/// A Redis connection ready for use
///
/// # Panics
/// Panics if unable to connect to Redis
pub fn configure_redis() -> redis::Connection {
    let redis_host_name = &AuthServiceSetting::load().redis.host_name;

    get_redis_client(redis_host_name)
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}

/// Create a PostgreSQL connection pool
///
/// # Arguments
/// * `url` - Database connection URL
///
/// # Returns
/// Result containing the PgPool or an error
pub async fn get_postgres_pool(url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new().max_connections(5).connect(url).await
}

/// Create a Redis client
///
/// # Arguments
/// * `redis_hostname` - Redis server hostname
///
/// # Returns
/// Result containing the Redis client or an error
pub fn get_redis_client(redis_hostname: &str) -> RedisResult<Client> {
    let redis_url = format!("redis://{}/", redis_hostname);
    redis::Client::open(redis_url)
}
