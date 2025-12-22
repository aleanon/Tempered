# Architecture Documentation

## Overview

This authentication library is designed to be **framework-agnostic**, allowing it to work with any Rust web framework (Axum, Actix, Rocket, Warp, etc.) with zero runtime overhead through compile-time monomorphization.

## Architectural Layers

### 1. Core Domain Layer (`tempered_core`)

**Purpose:** Pure domain logic with no framework dependencies.

**Key Traits:**
- `AuthenticationScheme` - Core authentication logic
- `SupportsTwoFactor` - 2FA capability marker
- `SupportsTokenRevocation` - Token revocation capability marker

**Principles:**
- No HTTP dependencies
- No serialization dependencies (no serde in core domain entities)
- Pure business logic only
- Framework-agnostic by design

### 2. Adapters Layer (`tempered_adapters`)

**Purpose:** Bridges domain logic to HTTP frameworks without coupling to any specific framework.

This layer contains three sub-layers:

#### 2a. HTTP Abstraction (`http/http_abstraction.rs`)

Defines framework-agnostic HTTP traits that any framework can implement:

```rust
pub trait AuthRequest {
    fn header(&self, name: &str) -> Option<&str>;
    fn cookie(&self, name: &str) -> Option<&str>;
    fn method(&self) -> &str;
    fn path(&self) -> &str;
}

pub trait AuthResponseBuilder: Sized {
    type Response;
    fn status(self, code: u16) -> Self;
    fn header(self, name: &str, value: &str) -> Self;
    fn cookie(self, cookie: &str) -> Self;
    fn json_body(self, body: serde_json::Value) -> Self;
    fn build(self) -> Self::Response;
}
```

**Why traits instead of concrete types?**
- **Zero-cost abstractions:** Frameworks implement traits on their own types (no wrapper allocations)
- **Compile-time polymorphism:** Monomorphization generates optimized code for each framework
- **No orphan rule violations:** Traits are defined in the same crate where they're implemented

#### 2b. Framework-Agnostic Handlers (`handlers/`)

Pure business logic functions that work with any framework:

```rust
pub async fn handle_login<S, B>(
    scheme: &S,
    credentials: S::Credentials,
    builder: B,
) -> Result<B::Response, String>
where
    S: HttpAuthenticationScheme,
    B: AuthResponseBuilder,
{
    let outcome = scheme.login(credentials).await?;
    Ok(scheme.create_login_response(builder, outcome))
}
```

**Key characteristics:**
- Generic over authentication scheme and response builder
- No framework-specific types
- Pure functions (no extractors, no framework state)
- Can be tested without any HTTP framework

#### 2c. Framework-Specific Routes (`http/axum_routes/`)

Framework-specific code that extracts data and calls handlers:

```rust
pub async fn login<S>(
    State(scheme): State<S>,
    Json(credentials): Json<S::Credentials>,
) -> Result<impl IntoResponse, LoginError>
where
    S: HttpAuthenticationScheme,
{
    let builder = response_builder();
    handlers::handle_login(&scheme, credentials, builder)
        .await
        .map_err(LoginError::AuthenticationFailed)
}
```

**Responsibilities:**
- Use framework extractors (`State`, `Json`, etc.)
- Convert framework types to handler inputs
- Call framework-agnostic handlers
- Convert handler results to framework responses

### 3. Framework Adapters (`http/axum_adapters.rs`)

**Purpose:** Implement HTTP traits for specific framework types.

Example for Axum:
```rust
impl AuthRequest for axum::http::Request<Body> {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers().get(name)?.to_str().ok()
    }
    // ... other methods
}

impl AuthResponseBuilder for AxumResponseBuilder {
    type Response = Response<Body>;
    // ... builder methods
}
```

**Why this works:**
- `AuthRequest` and `AuthResponseBuilder` traits are in `tempered_adapters`
- Axum types are from the `axum` crate
- Implementation is also in `tempered_adapters`
- **No orphan rule violation:** At least one type (the trait) is local

## Zero-Cost Abstraction Strategy

### The Problem: Framework Coupling

Initial approach had routes directly dependent on Axum:
```rust
// ❌ Tightly coupled to Axum
pub async fn login(
    State(scheme): State<JwtScheme>,
    Json(credentials): Json<LoginCredentials>,
) -> Response<Body>
```

### The Solution: Three-Layer Architecture

1. **Domain Layer:** `AuthenticationScheme` trait (pure logic)
2. **Handler Layer:** Generic functions using HTTP traits (framework-agnostic)
3. **Route Layer:** Framework extractors → handlers → framework responses

### Why Not Use Concrete HTTP Types?

We considered using the `http` crate's concrete types (`http::Request`, `http::Response`), but this would require:
- Converting framework types to `http` types (allocation overhead)
- Converting back to framework types (more allocations)
- Losing framework-specific features

**Trait-based approach wins:**
```rust
// Zero allocations - compiles to direct method calls
impl AuthRequest for axum::Request<Body> {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers().get(name)?.to_str().ok() // Direct access
    }
}
```

At compile time, Rust monomorphizes this to:
```rust
// What the compiler actually generates
fn handle_login_axum(scheme: &JwtScheme, ...) {
    let header = axum_request.headers().get(name); // Direct call, no indirection
}
```

## Orphan Rule Solution

### The Orphan Rule

Rust's orphan rule states: You can only implement a trait if either:
- The trait is defined in your crate, OR
- The type is defined in your crate

### Initial Problem

We wanted:
```rust
// tempered_core defines AuthRequest
// axum crate defines Request<Body>
// tempered_adapters tries to implement

impl AuthRequest for Request<Body> { } // ❌ Orphan rule violation!
```

Neither `AuthRequest` nor `Request<Body>` are local to `tempered_adapters`.

### Solution: Move Traits to Adapters

By moving HTTP abstraction traits from `tempered_core` to `tempered_adapters`:
```rust
// tempered_adapters/src/http/http_abstraction.rs
pub trait AuthRequest { }

// tempered_adapters/src/http/axum_adapters.rs
impl AuthRequest for Request<Body> { } // ✅ AuthRequest is local!
```

**Why this works:**
- `AuthRequest` is now local to `tempered_adapters`
- Satisfies orphan rule: local trait, foreign type
- Still achieves framework independence (domain layer doesn't need HTTP traits)

## Adding Support for New Frameworks

To add support for a new framework (e.g., Actix Web):

### Step 1: Implement HTTP Traits

Create `tempered_adapters/src/http/actix_adapters.rs`:
```rust
impl AuthRequest for actix_web::HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers().get(name)?.to_str().ok()
    }
    // ... implement other methods
}

pub struct ActixResponseBuilder { /* ... */ }

impl AuthResponseBuilder for ActixResponseBuilder {
    type Response = actix_web::HttpResponse;
    // ... implement builder methods
}
```

### Step 2: Create Framework-Specific Routes

Create `tempered_adapters/src/http/actix_routes/`:
```rust
pub async fn login<S>(
    scheme: web::Data<S>,
    credentials: web::Json<S::Credentials>,
) -> Result<HttpResponse, Error>
where
    S: HttpAuthenticationScheme,
{
    let builder = actix_response_builder();
    handlers::handle_login(&scheme, credentials.into_inner(), builder)
        .await
        .map_err(|e| actix_web::error::ErrorUnauthorized(e))
}
```

### Step 3: Export in Module

Update `tempered_adapters/src/http/mod.rs`:
```rust
pub mod actix_adapters;
pub mod actix_routes;
```

**That's it!** The framework-agnostic handlers work without modification.

## Benefits of This Architecture

### 1. Framework Independence
- Swap frameworks without changing business logic
- Support multiple frameworks simultaneously
- Test authentication logic without any HTTP framework

### 2. Zero Runtime Overhead
- Traits compile to direct function calls (monomorphization)
- No allocations for type conversions
- No virtual dispatch (no `dyn Trait`)

### 3. Type Safety
- Compiler ensures all framework implementations satisfy contracts
- Cannot accidentally use framework-specific types in handlers
- Generic constraints enforce capabilities (e.g., `SupportsTwoFactor`)

### 4. Separation of Concerns
- Domain logic: `tempered_core`
- HTTP abstraction: `tempered_adapters/http/http_abstraction.rs`
- Framework adapters: `tempered_adapters/http/{framework}_adapters.rs`
- Business logic: `tempered_adapters/handlers/`
- HTTP routes: `tempered_adapters/http/{framework}_routes/`

### 5. Testability
- Test handlers with mock HTTP traits (no real framework needed)
- Test domain logic in isolation
- Integration tests only needed for framework-specific routes

## Example: Complete Request Flow

### 1. Axum receives HTTP request
```
POST /login
Content-Type: application/json
{"email": "user@example.com", "password": "secret"}
```

### 2. Axum route extracts data
```rust
// axum_routes/login.rs
pub async fn login<S>(
    State(scheme): State<S>,           // Extract auth scheme from app state
    Json(credentials): Json<S::Credentials>, // Extract JSON body
) -> Result<impl IntoResponse, LoginError>
```

### 3. Route calls framework-agnostic handler
```rust
let builder = response_builder(); // Create Axum response builder
handlers::handle_login(&scheme, credentials, builder).await
```

### 4. Handler executes business logic
```rust
// handlers/login.rs (generic over scheme and builder)
pub async fn handle_login<S, B>(
    scheme: &S,
    credentials: S::Credentials,
    builder: B,
) -> Result<B::Response, String>
{
    let outcome = scheme.login(credentials).await?;  // Domain logic
    Ok(scheme.create_login_response(builder, outcome)) // Build response
}
```

### 5. Scheme creates HTTP response
```rust
// authentication/jwt_scheme.rs
impl HttpAuthenticationScheme for JwtScheme {
    fn create_login_response<B: AuthResponseBuilder>(
        &self,
        builder: B,
        outcome: LoginOutcome<Self::Token>,
    ) -> B::Response {
        match outcome {
            LoginOutcome::Success(token) => {
                builder
                    .status(200)
                    .cookie(&create_auth_cookie(token))
                    .json_body(json!({"status": "success"}))
                    .build()
            }
            // ... other outcomes
        }
    }
}
```

### 6. Response builder creates Axum response
```rust
// axum_adapters.rs
impl AuthResponseBuilder for AxumResponseBuilder {
    type Response = Response<Body>;
    
    fn build(self) -> Self::Response {
        let body = self.body.unwrap_or_default();
        self.builder
            .body(Body::from(body))
            .unwrap_or_else(|_| Response::new(Body::empty()))
    }
}
```

### 7. Axum sends HTTP response
```
HTTP/1.1 200 OK
Set-Cookie: auth_token=eyJ...; HttpOnly; Secure; SameSite=Strict
Content-Type: application/json

{"status": "success"}
```

## Compile-Time Optimizations

The Rust compiler performs several optimizations:

### 1. Monomorphization
Generic functions are compiled to specific implementations:
```rust
// Source code (generic)
fn handle_login<S, B>(scheme: &S, ...) { }

// Compiled code (monomorphized)
fn handle_login_jwt_axum(scheme: &JwtScheme, ...) { }
fn handle_login_apikey_actix(scheme: &ApiKeyScheme, ...) { }
```

### 2. Inline Expansion
Trait method calls are inlined:
```rust
// Source
let header = request.header("Authorization");

// Compiled (inlined)
let header = request.headers().get("Authorization")?.to_str().ok();
```

### 3. Dead Code Elimination
Unused authentication schemes are removed:
```rust
// If you only use JWT, compiler removes ApiKey implementation entirely
```

### 4. Zero-Sized Types
Stateless schemes compile to zero size:
```rust
struct StatelessScheme;  // Zero bytes at runtime
```

## Migration Path

### Old Code (Tightly Coupled)
```rust
// routes/login.rs
pub async fn login(
    State(scheme): State<JwtScheme>,
    Json(credentials): Json<LoginCredentials>,
) -> Response<Body> {
    // JWT-specific logic mixed with HTTP logic
}
```

### New Code (Framework-Agnostic)
```rust
// handlers/login.rs (generic)
pub async fn handle_login<S, B>(scheme: &S, ...) -> Result<B::Response, String>

// axum_routes/login.rs (framework-specific)
pub async fn login<S>(State(scheme): State<S>, ...) -> Result<impl IntoResponse, Error> {
    handlers::handle_login(&scheme, credentials, builder).await
}
```

**Benefits:**
- Same handler works with Actix, Rocket, Warp
- Test business logic without Axum
- Swap authentication schemes without changing routes

## Performance Characteristics

| Operation | Cost | Notes |
|-----------|------|-------|
| Trait method call | Zero | Inlined by compiler |
| Type conversion | Zero | Traits on native types |
| Virtual dispatch | Zero | No `dyn Trait` used |
| Allocation | Zero | No intermediate wrappers |
| Runtime checks | Zero | All checks at compile time |

This architecture achieves the holy grail: **maximum flexibility with zero runtime cost**.

## File Structure

```
tempered_core/
  src/
    strategies/           # AuthenticationScheme implementations
    domain/              # Domain entities and traits

tempered_adapters/
  src/
    http/
      http_abstraction.rs        # AuthRequest, AuthResponseBuilder traits
      http_authentication_scheme.rs  # HttpAuthenticationScheme trait
      
      axum_adapters.rs          # Axum trait implementations
      axum_routes/              # Axum-specific routes
        login.rs
        logout.rs
        verify_2fa.rs
      
      # Future: actix_adapters.rs, actix_routes/, etc.
    
    handlers/                   # Framework-agnostic business logic
      login.rs
      logout.rs
      verify_2fa.rs
    
    authentication/            # Authentication scheme implementations
      jwt_scheme.rs
```

## Key Design Principles

1. **Dependency Inversion:** High-level logic doesn't depend on low-level frameworks
2. **Interface Segregation:** Separate traits for different capabilities (2FA, token revocation)
3. **Zero-Cost Abstractions:** No runtime overhead for framework independence
4. **Compile-Time Safety:** Type system enforces correct usage
5. **Separation of Concerns:** Clear boundaries between layers

## Conclusion

This architecture provides a production-ready, framework-agnostic authentication library that:
- Works with any Rust web framework
- Has zero runtime overhead
- Maintains type safety
- Enables easy testing
- Supports multiple authentication schemes
- Allows mixing frameworks in the same application

The key insight is using **trait-based adapters** instead of concrete types, leveraging Rust's powerful compile-time polymorphism to achieve both flexibility and performance.
