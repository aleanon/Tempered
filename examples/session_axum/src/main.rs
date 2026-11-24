//! Standalone Axum example crate: the `jwt_standalone` app with server-side
//! sessions instead of JWTs (login, signup, 2FA, elevation/"sudo", password
//! reset), served with the same frontend.
//!
//! ```bash
//! cargo run -p tempered-example-session                          # in-memory sessions
//! REDIS_HOST_NAME=127.0.0.1 cargo run -p tempered-example-session # Redis sessions
//! # open http://localhost:3000
//! ```
//!
//! A session cookie holds only a random id; the session lives in a
//! `SessionStore`. That makes logout and "log out everywhere" instant (the
//! session is deleted), and caps how long a stolen cookie works: an idle
//! session expires after its TTL, and every session after its maximum
//! lifetime however busy it is. With `REDIS_HOST_NAME` set the sessions live
//! in Redis and survive a restart of this process; without it they are
//! in memory.
//!
//! The whole app is written once, generic over the store (`serve`), and
//! `main` picks the store.

use axum::{Extension, Router, routing::get};
use tempered::{
    Email, EmailClient, ExposeSecret, HashMapPasswordResetTokenStore, HashMapSessionStore,
    HashMapTwoFaCodeStore, HashMapUserStore, RedisSessionStore, SessionClaims, SessionConfig,
    SessionScheme, SessionStore, async_trait, auth_service,
};

/// The JWT example's frontend: it only calls `/login`, `/signup` and
/// `/verify-2fa`, which a session scheme serves the same way.
const ASSETS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../jwt_standalone/assets");

/// Idle timeout of a login session.
const SESSION_TTL_SECONDS: u64 = 3600;
/// Elevated ("sudo") sessions are short.
const ELEVATED_TTL_SECONDS: u64 = 900;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    match std::env::var("REDIS_HOST_NAME") {
        Ok(host) => {
            let client = redis::Client::open(format!("redis://{host}:6379"))?;
            // One multiplexed, reconnecting connection, cloned into each store.
            let connection = redis::aio::ConnectionManager::new(client).await?;
            println!("sessions in Redis at {host}");
            // Same server, separate namespaces: the two kinds of session
            // share no keys, so logging out of one leaves the other alone.
            serve(
                RedisSessionStore::new(connection.clone(), SESSION_TTL_SECONDS),
                RedisSessionStore::with_namespace(connection, ELEVATED_TTL_SECONDS, "elevated"),
            )
            .await
        }
        Err(_) => {
            println!("sessions in memory (set REDIS_HOST_NAME to use Redis)");
            serve(HashMapSessionStore::new(), HashMapSessionStore::new()).await
        }
    }
}

/// Build and run the app over any session store. The elevated sessions get
/// their own store (in Redis: the same server, with a shorter TTL) and
/// cookie, so a stolen login cookie is not a sudo cookie.
async fn serve<S>(sessions: S, elevated: S) -> Result<(), Box<dyn std::error::Error>>
where
    S: SessionStore + Clone + Send + Sync + 'static,
{
    let email = PrintingEmailClient;
    let scheme = SessionScheme::new(
        HashMapUserStore::new(),
        sessions,
        // Absolute lifetime: the 24 h default (`.max_lifetime(seconds)` to
        // change it).
        SessionConfig::new("__Host-session", SESSION_TTL_SECONDS),
    )
    .supports_registration()
    .supports_2fa(HashMapTwoFaCodeStore::new(), email.clone())
    .supports_elevation(
        elevated,
        SessionConfig::new("__Host-elevated_session", ELEVATED_TTL_SECONDS),
        |e| e.supports_password_change().supports_account_deletion(),
    )
    .supports_password_reset(HashMapPasswordResetTokenStore::new(), email);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    println!("listening on http://localhost:3000");
    auth_service(scheme, ASSETS.to_string())
        // The frontend's flat elevation paths (defaults are `/elevated/...`).
        .verify_elevated_token("/verify-elevated-token")
        .change_password("/change-password")
        .delete_account("/delete-account")
        .validated_router(Router::new().route("/whoami", get(whoami)))
        .validated_elevated_router(Router::new().route("/secret", get(secret)))
        .run(listener)
        .await?;
    Ok(())
}

/// Login-protected: reachable with a valid session cookie.
async fn whoami(Extension(claims): Extension<SessionClaims>) -> String {
    format!("logged in as {}", claims.email.as_ref().expose_secret())
}

/// Elevation-protected: reachable only with a valid elevated session.
async fn secret(Extension(claims): Extension<SessionClaims>) -> String {
    format!(
        "elevated access granted to {}",
        claims.email.as_ref().expose_secret()
    )
}

/// Prints mail (2FA codes, reset links) to stdout instead of sending it.
#[derive(Clone)]
struct PrintingEmailClient;

#[async_trait]
impl EmailClient for PrintingEmailClient {
    async fn send_email(
        &self,
        recipient: &Email,
        subject: &str,
        content: &str,
    ) -> Result<(), String> {
        println!(
            "[email] to={} subject={subject} content={content}",
            recipient.as_ref().expose_secret()
        );
        Ok(())
    }
}
