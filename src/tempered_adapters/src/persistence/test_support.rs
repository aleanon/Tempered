//! Containers for the store tests (Docker must be running).

#[cfg(feature = "redis")]
pub(crate) mod redis {
    use ::redis::aio::ConnectionManager;
    use testcontainers_modules::{
        redis::Redis,
        testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner},
    };

    /// A fresh Redis and a connection to it. Keep the container alive for as
    /// long as the connection is used.
    pub(crate) async fn connection() -> (ContainerAsync<Redis>, ConnectionManager) {
        // The stores use GETDEL / GETEX (Redis 6.2+); the module's default
        // image is older.
        let container = Redis::default()
            .with_tag("7.4")
            .start()
            .await
            .expect("Failed to start Redis");
        let host = container.get_host().await.expect("Redis host");
        let port = container
            .get_host_port_ipv4(6379)
            .await
            .expect("Redis port");
        let client =
            ::redis::Client::open(format!("redis://{host}:{port}/")).expect("Redis client");
        let connection = ConnectionManager::new(client)
            .await
            .expect("Redis connection");
        (container, connection)
    }
}

#[cfg(feature = "postgres")]
pub(crate) mod postgres {
    use sqlx::PgPool;
    use testcontainers_modules::{
        postgres::Postgres,
        testcontainers::{ContainerAsync, runners::AsyncRunner},
    };

    /// A fresh, migrated Postgres. Keep the container alive for as long as the
    /// pool is used.
    pub(crate) async fn pool() -> (ContainerAsync<Postgres>, PgPool) {
        let container = Postgres::default()
            .start()
            .await
            .expect("Failed to start Postgres");
        let host = container.get_host().await.expect("Postgres host");
        let port = container
            .get_host_port_ipv4(5432)
            .await
            .expect("Postgres port");
        let pool = super::super::postgres_user_store::get_postgres_pool(
            &format!("postgres://postgres:postgres@{host}:{port}"),
            5,
        )
        .await
        .expect("Failed to connect to Postgres");
        sqlx::migrate!()
            .run(&pool)
            .await
            .expect("Failed to migrate");
        (container, pool)
    }
}
