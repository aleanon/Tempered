use testcontainers_modules::postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

#[tokio::test]
async fn test_postgres_container_starts() {
    let _container = postgres::Postgres::default().start().await.unwrap();
}
