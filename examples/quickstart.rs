//! The README quickstart, kept here so it is compiled with the workspace.
//! If you change this file, mirror the change in `README.md`.
//!
//! ```bash
//! JWT_SECRET=$(openssl rand -base64 48) cargo run --example quickstart
//! ```

use axum::{Extension, Router, routing::get};
use tempered::{
    Claims, ExposeSecret, HashMapTokenEpochStore, HashMapUserStore, HashSetBannedTokenStore,
    JwtAuthConfig, JwtScheme, Secret, auth_service,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let jwt_config = JwtAuthConfig {
        jwt_cookie_name: "jwt".to_string(),
        // Load this from the environment in real code. Shorter than 32 bytes
        // panics at startup (`openssl rand -base64 48` makes a good one).
        jwt_secret: Secret::new(std::env::var("JWT_SECRET")?),
        token_ttl_in_seconds: 3600,
        // When set, tokens carry these claims and validation requires them, so a
        // token signed with the same secret for another service is rejected.
        audience: Some("my-app".to_string()),
        issuer: Some("my-app".to_string()),
    };

    // Declare the scheme and the capabilities you want. Each `supports_*` call
    // auto-wires its route(s) in `auth_service` below — there are no route
    // opt-ins to remember.
    let scheme = JwtScheme::new(
        HashMapUserStore::new(), // swap for PostgresUserStore in production
        jwt_config,
        HashSetBannedTokenStore::new(), // swap for RedisBannedTokenStore in production
        HashMapTokenEpochStore::new(),  // swap for RedisTokenEpochStore in production
    )
    .supports_registration()
    .build();

    // `auth_service` reads the declared capabilities and mounts the routes
    // (`/login`, `/logout`, `/signup`, `/verify-token`, ...) at the right authz
    // level. `assets_dir` serves an optional SPA; pass an empty dir for API-only.
    let service = auth_service(scheme, "assets".to_string())
        // Attach your own protected routes — see below.
        .validated_router(Router::new().route("/whoami", get(whoami)));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    service.run(listener).await?;
    Ok(())
}

// A login-protected handler. The login middleware validates the `jwt` cookie and
// injects `Claims` into the request extensions, so your handler just extracts it
// — you never name the scheme's generic type.
async fn whoami(Extension(claims): Extension<Claims>) -> String {
    format!("logged in as {}", claims.sub.expose_secret())
}
