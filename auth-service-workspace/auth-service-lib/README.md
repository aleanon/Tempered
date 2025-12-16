# Auth Service Library

A reusable authentication service library built with clean hexagonal architecture principles. This library provides a complete authentication system that can be used as a standalone service or nested into existing applications.

## Features

- **Complete Authentication System**
  - User signup with optional 2FA
  - Login with 2FA support
  - Token-based authentication (JWT)
  - Elevated permissions with re-authentication
  - Password change functionality
  - Account deletion

- **Clean Architecture**
  - Framework-agnostic business logic
  - Testable use cases
  - Pluggable infrastructure adapters
  - Clear separation of concerns

- **Flexible Deployment**
  - Run as standalone service
  - Nest into existing Axum applications
  - Configurable CORS support

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
auth-service-lib = { path = "../auth-service-lib" }
auth-adapters = { path = "../auth-adapters" }
auth-core = { path = "../auth-core" }
```

## Quick Start

### Standalone Service

```rust
use auth_service_lib::AuthService;
use auth_adapters::persistence::{PostgresUserStore, RedisBannedTokenStore, RedisTwoFaCodeStore};
use auth_adapters::email::PostmarkEmailClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup your stores
    let user_store = PostgresUserStore::new(pg_pool);
    let banned_token_store = RedisBannedTokenStore::new(redis_conn, ttl);
    let two_fa_code_store = RedisTwoFaCodeStore::new(redis_conn);
    let email_client = PostmarkEmailClient::new(base_url, sender, token, http_client);

    // Create the auth service
    let auth_service = AuthService::new(
        user_store,
        banned_token_store,
        two_fa_code_store,
        email_client,
    );

    // Run as standalone server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    let allowed_origins = vec!["http://localhost:8000".to_string()];
    
    auth_service
        .run_standalone(listener, Some(allowed_origins))
        .await?;

    Ok(())
}
```

### Nested Router

Use the auth service as part of a larger application:

```rust
use auth_service_lib::AuthService;
use axum::Router;

let auth_service = AuthService::new(
    user_store,
    banned_token_store,
    two_fa_code_store,
    email_client,
);

// Get the router without starting a server
let auth_router = auth_service.as_nested_router(Some(allowed_origins));

// Mount it in your main application
let app = Router::new()
    .nest("/auth", auth_router)
    .route("/", get(home))
    .route("/api/data", get(data));
```

## API Endpoints

The auth service provides the following endpoints:

- `POST /signup` - Register a new user
- `POST /login` - Authenticate and get JWT token
- `POST /logout` - Invalidate JWT token
- `POST /verify-2fa` - Complete 2FA verification
- `POST /verify-token` - Validate a JWT token
- `POST /elevate` - Get elevated permissions
- `POST /change-password` - Update user password (requires elevated token)
- `DELETE /delete-account` - Delete user account (requires elevated token)

## Helper Functions

The library provides convenience functions for common setup tasks:

```rust
use auth_service_lib::{configure_postgresql, configure_redis};

// Setup Postgres with migrations
let pg_pool = configure_postgresql().await;

// Setup Redis connection
let redis_conn = configure_redis();
```

## Architecture

The library follows hexagonal architecture with clear boundaries:

```
auth-service-lib/
├── src/
│   ├── auth_service.rs    # Main service struct
│   ├── helpers.rs          # Configuration helpers
│   └── lib.rs              # Public API
```

**Dependencies:**
- `auth-core` - Domain entities and port traits
- `auth-adapters` - Infrastructure implementations (HTTP, DB, email)

## Example: main_with_lib.rs

See `auth-service-bin/src/main_with_lib.rs` for a complete example of using this library.

## Benefits

1. **Reusable** - Use the same auth service across multiple applications
2. **Testable** - Business logic is separated from infrastructure
3. **Flexible** - Swap out implementations (different databases, email providers)
4. **Maintainable** - Clear boundaries and responsibilities
5. **Type-Safe** - Leverage Rust's type system for correctness

## License

[Your License]
