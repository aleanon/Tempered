//! Standalone Axum example crate: the full JWT auth service (login, signup,
//! 2FA, elevation/"sudo", password reset), served with the bundled frontend in
//! `assets/` (the original bootcamp UI).
//!
//! ```bash
//! cargo run -p tempered-example-jwt
//! # open http://localhost:3000
//! ```

use axum::{Extension, Router, routing::get};
use tempered::{
    Claims, Email, EmailClient, ExposeSecret, HashMapPasswordResetTokenStore,
    HashMapTokenEpochStore, HashMapTwoFaCodeStore, HashMapUserStore, HashSetBannedTokenStore,
    JwtAuthConfig, JwtScheme, Secret, async_trait, auth_service,
};
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

    // Demo only: read secrets from the environment, falling back to clearly-
    // labelled insecure values. Production must supply strong random secrets.
    // Binding aud/iss means a token signed with the same secret for another
    // service or environment is rejected here.
    let jwt_config = JwtAuthConfig {
        jwt_cookie_name: "jwt".to_string(),
        jwt_secret: Secret::new(
            std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "dev-only-insecure-change-me-0123456789abcd".to_string()),
        ),
        token_ttl_in_seconds: 3600,
        audience: Some("tempered-example".to_string()),
        issuer: Some("tempered-example".to_string()),
    };

    let elevated_jwt_config = JwtAuthConfig {
        jwt_cookie_name: "elevated_jwt".to_string(),
        jwt_secret: Secret::new(
            std::env::var("JWT_ELEVATED_SECRET")
                .unwrap_or_else(|_| "dev-only-insecure-elevated-change-me-9876543210".to_string()),
        ),
        token_ttl_in_seconds: 900, // 15 minutes for elevated tokens
        audience: Some("tempered-example".to_string()),
        issuer: Some("tempered-example".to_string()),
    };

    let banned_token_store = HashSetBannedTokenStore::new();
    let elevated_banned_token_store = HashSetBannedTokenStore::new();
    let password_reset_token_store = HashMapPasswordResetTokenStore::new();

    // Build the scheme from a minimal core, opting into each capability. Only
    // Declare capabilities on the scheme; each `supports_*` auto-wires its route
    // in `auth_service` below — no route opt-ins needed there.
    // The epoch store makes password change / account deletion revoke every
    // outstanding token (in-memory here; use RedisTokenEpochStore in production).
    let jwt_scheme = JwtScheme::new(
        user_store,
        jwt_config,
        banned_token_store,
        HashMapTokenEpochStore::new(),
    )
    .supports_registration()
    .supports_2fa(two_fa_code_store, email_client.clone())
    .supports_elevation(
        elevated_banned_token_store,
        elevated_jwt_config,
        |elevated| {
            elevated
                .supports_password_change()
                .supports_account_deletion()
        },
    )
    .supports_password_reset(password_reset_token_store, email_client)
    .build();

    let auth_service = auth_service(jwt_scheme, ASSETS.to_string())
        // Keep the flat elevation paths this frontend expects (defaults would be
        // `/elevated/...`).
        .verify_elevated_token("/verify-elevated-token")
        .change_password("/change-password")
        .delete_account("/delete-account")
        // Attach your own routers, protected by the auth service. `/whoami` needs
        // a valid login session; `/secret` needs an elevated ("sudo") token.
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
