//! Standalone Axum example crate: the full JWT auth service (login, signup,
//! 2FA, elevation/"sudo", password reset), served with the bundled frontend in
//! `assets/` (the original bootcamp UI).
//!
//! ```bash
//! cargo run -p tempered-example-jwt
//! # open http://localhost:3000
//! ```

use axum::{Extension, Router, routing::get};
use tempered::adapters::auth::local_jwt_validator::Claims;
use tempered::{
    Email, EmailClient, ExposeSecret, HashMapPasswordResetTokenStore, HashMapTwoFaCodeStore,
    HashMapUserStore, HashSetBannedTokenStore, JwtAuthConfig, JwtScheme, Secret, async_trait,
};
use tempered_axum::auth_service::auth_service;
use tracing_error::ErrorLayer;
use tracing_subscriber::{
    EnvFilter, filter::ParseError, fmt, layer::SubscriberExt, util::SubscriberInitExt,
};

const ASSETS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/assets");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing().expect("Failed to initialize tracing");

    let user_store = HashMapUserStore::new();
    let two_fa_code_store = HashMapTwoFaCodeStore::new();
    let email_client = DummyEmailClient;

    let jwt_config = JwtAuthConfig {
        jwt_cookie_name: "jwt".to_string(),
        jwt_secret: Secret::new("input a long random generated string here".to_string()),
        token_ttl_in_seconds: 3600,
    };

    let elevated_jwt_config = JwtAuthConfig {
        jwt_cookie_name: "elevated_jwt".to_string(),
        jwt_secret: Secret::new("input another long random generated string here".to_string()),
        token_ttl_in_seconds: 900, // 15 minutes for elevated tokens
    };

    let banned_token_store = HashSetBannedTokenStore::new();
    let elevated_banned_token_store = HashSetBannedTokenStore::new();
    let password_reset_token_store = HashMapPasswordResetTokenStore::new();

    // Build the scheme from a minimal core, opting into each capability. Only
    // the `supports_*` methods that were called light up the matching trait —
    // so `auth_service(...).with_2fa(...)` below only compiles because of them.
    let jwt_scheme = JwtScheme::new(user_store, jwt_config, banned_token_store)
        .supports_2fa(two_fa_code_store, email_client.clone())
        .supports_elevation(elevated_banned_token_store, elevated_jwt_config, |elevated| {
            elevated
                .supports_password_change()
                .supports_account_deletion()
        })
        .supports_password_reset(password_reset_token_store, email_client)
        .build();

    let auth_service = auth_service(jwt_scheme, ASSETS.to_string())
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
        )
        .with_password_reset(None, None)
        // Attach your own routers, protected by the auth service. `/whoami`
        // needs a valid login session; `/secret` needs an elevated ("sudo")
        // token (obtained via `/elevate`). Their handlers read the logged-in
        // user from the `Claims` the middleware inserts into request extensions.
        .validated_router(Router::new().route("/whoami", get(whoami)))
        .validated_elevated_router(Router::new().route("/secret", get(secret)));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    auth_service.run(listener).await?;

    Ok(())
}

/// Login-protected: reachable with a valid `jwt` session cookie.
async fn whoami(Extension(claims): Extension<Claims>) -> String {
    format!("logged in as {}", claims.sub.expose_secret())
}

/// Elevation-protected: reachable only with a valid elevated token.
async fn secret(Extension(claims): Extension<Claims>) -> String {
    format!("elevated access granted to {}", claims.sub.expose_secret())
}

fn init_tracing() -> Result<(), ParseError> {
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
            "[email] to={} subject={} content={}",
            recipient.as_ref().expose_secret(),
            subject,
            content
        );
        Ok(())
    }
}
