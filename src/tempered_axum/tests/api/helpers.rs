use std::{sync::Arc, time::Duration};

use reqwest::{
    Client, Url,
    cookie::{CookieStore, Jar},
};
use secrecy::Secret;
use serde::Serialize;
use serde_json::Value;
use sqlx::PgPool;
use tempered_adapters::{
    auth_validation::local_jwt_validator::JwtAuthConfig,
    authentication::jwt_scheme::JwtScheme,
    email::PostmarkEmailClient,
    persistence::{
        PostgresUserStore, RedisBannedTokenStore, RedisTwoFaCodeStore,
        postgres_user_store::get_postgres_pool,
    },
};
use tempered_axum::auth_service::auth_service;
use tempered_core::{Email, TwoFaAttemptId};
use testcontainers_modules::{
    postgres,
    redis::Redis,
    testcontainers::{ContainerAsync, runners::AsyncRunner},
};
use tokio::{net::TcpListener, sync::RwLock};
use uuid::Uuid;
use wiremock::MockServer;

// Test constants for JWT cookies
pub const JWT_COOKIE_NAME: &str = "jwt";
pub const JWT_ELEVATED_COOKIE_NAME: &str = "elevated_jwt";
pub const JWT_SECRET: &str = "secret";
pub const JWT_ELEVATED_SECRET: &str = "elevated_secret";

// Test constants for email client
pub const SENDER: &str = "test@email.com";
pub const TIMEOUT: Duration = std::time::Duration::from_millis(200);

pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>,
    pub http_client: reqwest::Client,
    pub two_fa_code_store: RedisTwoFaCodeStore,
    pub banned_token_store: RedisBannedTokenStore,
    pub email_server: MockServer,
    #[allow(unused)]
    user_store_container: ContainerAsync<postgres::Postgres>,
    #[allow(unused)]
    redis_container: ContainerAsync<Redis>,
}

impl TestApp {
    pub async fn new() -> Self {
        let (redis_container, redis_connection) = setup_and_connect_redis_container().await;
        let redis_connection = Arc::new(RwLock::new(redis_connection));

        let banned_token_store = RedisBannedTokenStore::new(redis_connection.clone(), 600);
        let two_fa_code_store = RedisTwoFaCodeStore::new(redis_connection);

        let email_server = MockServer::start().await;
        let base_url = email_server.uri();
        let email_client = configure_postmark_email_client(base_url);

        let (user_store_container, pool) = setup_and_connect_user_store_container().await;

        let user_store = PostgresUserStore::new(pool);

        // Create JWT configuration for the scheme
        let jwt_config = JwtAuthConfig {
            jwt_cookie_name: JWT_COOKIE_NAME.to_string(),
            jwt_secret: Secret::new(JWT_SECRET.to_string()),
            token_ttl_in_seconds: 3600,
        };

        let elevated_jwt_config = JwtAuthConfig {
            jwt_cookie_name: JWT_ELEVATED_COOKIE_NAME.to_string(),
            jwt_secret: Secret::new(JWT_ELEVATED_SECRET.to_string()),
            token_ttl_in_seconds: 900, // 15 minutes for elevated tokens
        };

        // Create the JwtScheme with all required stores
        let jwt_scheme = JwtScheme::new(
            user_store,
            two_fa_code_store.clone(),
            email_client,
            banned_token_store.clone(),
            jwt_config,
            banned_token_store.clone(),
            elevated_jwt_config,
        );

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind to address");

        let address = format!("http://{}", listener.local_addr().unwrap());

        // Use the new builder pattern to configure the service with all features
        let app = auth_service(jwt_scheme, "./assets".to_string())
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

        let _ =
            tokio::spawn(async { app.run(listener).await.expect("Failed to run auth-service") });

        let cookie_jar = Arc::new(Jar::default());
        let http_client = reqwest::Client::builder()
            .cookie_provider(cookie_jar.clone())
            .build()
            .expect("Failed to build client");

        TestApp {
            address,
            cookie_jar,
            http_client,
            two_fa_code_store,
            banned_token_store,
            email_server,
            user_store_container,
            redis_container,
        }
    }

    pub fn add_invalid_cookie(&self, cookie_name: &str) {
        self.cookie_jar.add_cookie_str(
            &format!(
                "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
                cookie_name
            ),
            &Url::parse(&self.address).expect("Failed to parse URL"),
        );
    }

    pub fn get_jwt_token(&self) -> Option<String> {
        let cookie = self
            .cookie_jar
            .cookies(&Url::parse(&self.address).unwrap())?;

        let (_, token) = cookie.to_str().unwrap().split_once('=').unwrap();

        Some(token.to_owned())
    }

    pub fn get_token(&self, cookie_name: &str) -> Option<String> {
        self.cookie_jar
            .cookies(&Url::parse(&self.address).unwrap())?
            .to_str()
            .expect("Unable to make cookie into &str")
            .split(';')
            .map(|c| c.trim())
            .find(|c| c.starts_with(cookie_name))
            .and_then(|c| {
                c.split_once('=')
                    .and_then(|(_, token)| Some(token.to_owned()))
            })
    }

    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(&format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to execute request")
    }

    pub async fn post_signup<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/signup", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request")
    }

    pub async fn login<Body: Serialize>(&self, body: &Body) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request")
    }

    pub async fn logout(&self) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/logout", &self.address))
            .send()
            .await
            .expect("Failed to execute request")
    }

    pub async fn verify_2fa<Body: Serialize>(&self, body: &Body) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/verify-2fa", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request")
    }

    pub async fn verify_token(&self, token: &str) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/verify-token", &self.address))
            .header("Cookie", format!("jwt={}", token))
            .send()
            .await
            .expect("Failed to execute request")
    }

    pub async fn verify_elevated_token(&self, token: &str) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/verify-elevated-token", &self.address))
            .header("Cookie", format!("elevated_jwt={}", token))
            .send()
            .await
            .expect("Failed to execute request")
    }

    pub async fn delete_account(&self) -> reqwest::Response {
        self.http_client
            .delete(&format!("{}/delete-account", &self.address))
            .send()
            .await
            .expect("Failed to execute request")
    }

    pub async fn post_elevate<Body: Serialize>(&self, body: &Body) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/elevate", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request")
    }

    pub async fn post_change_password<Body: Serialize>(&self, body: &Body) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/change-password", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request")
    }

    pub async fn get_verify_two_fa_request(
        &self,
        email: &str,
        two_fa_attempt_id: TwoFaAttemptId,
    ) -> Value {
        let email_body = &self
            .email_server
            .received_requests()
            .await
            .expect("Request recording disabled")
            .get(0)
            .expect("No email received")
            .body
            .clone();

        let email_json: serde_json::Value =
            serde_json::from_slice(email_body).expect("Failed to parse email JSON");
        let code = email_json["TextBody"].as_str().expect("Missing content");

        serde_json::json!({
            "email": email,
            "2FACode": code,
            "loginAttemptId": two_fa_attempt_id.to_string(),
        })
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}

pub fn get_standard_test_user(two_fa: bool) -> Value {
    serde_json::json!({
        "email": "test@example.com",
        "password": "password",
        "requires2FA": two_fa
    })
}

fn configure_postmark_email_client(base_url: String) -> PostmarkEmailClient {
    let postmark_auth_token = Secret::new("auth_token".to_owned());

    let sender = Email::try_from(Secret::new(SENDER.to_owned())).unwrap();

    let http_client = Client::builder()
        .timeout(TIMEOUT)
        .build()
        .expect("Failed to build HTTP client");

    PostmarkEmailClient::new(base_url, sender, postmark_auth_token, http_client)
}

async fn setup_and_connect_user_store_container() -> (ContainerAsync<postgres::Postgres>, PgPool) {
    let container = postgres::Postgres::default()
        .start()
        .await
        .expect("Failed to start container");

    let db_port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("Failed to get the mapped port of the container");

    let host = container
        .get_host()
        .await
        .expect("Failed to get the container host address");

    let db_url = format!("postgres://postgres:postgres@{}:{}", host, db_port);

    let connection = get_postgres_pool(&db_url, 5)
        .await
        .expect("Failed to connect to database");

    sqlx::migrate!()
        .run(&connection)
        .await
        .expect("Failed to migrate the database");

    (container, connection)
}

async fn setup_and_connect_redis_container() -> (ContainerAsync<Redis>, redis::Connection) {
    let container = Redis::default()
        .start()
        .await
        .expect("Failed to start container");

    let db_port = container
        .get_host_port_ipv4(6379)
        .await
        .expect("Failed to get the mapped port of the container");

    let host = container
        .get_host()
        .await
        .expect("Failed to get the container host address");

    let db_url = format!("redis://{}:{}/", host, db_port);

    let connection = redis::Client::open(db_url)
        .expect("Failed to open redis client")
        .get_connection()
        .expect("Failed to connect redis client");

    (container, connection)
}
