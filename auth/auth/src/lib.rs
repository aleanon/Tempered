//! # Auth - Authentication Service Library
//!
//! This is a facade crate that re-exports all public APIs from the auth service components.
//! Use this crate to get access to all authentication functionality in one place.
//!
//! ## Usage
//!
//! Add to your `Cargo.toml`:
//! ```toml
//! [dependencies]
//! auth = { path = "../auth" }
//! ```
//!
//! ## Structure
//!
//! - **Core domain types**: `Email`, `Password`, `User`, etc.
//! - **Repository traits**: `UserStore`, `BannedTokenStore`, `TwoFaCodeStore`
//! - **Use cases**: `SignupUseCase`, `LoginUseCase`, etc.
//! - **Adapters**: `PostgresUserStore`, `RedisBannedTokenStore`, `PostmarkEmailClient`, etc.
//! - **Service**: `AuthService` - The main entry point for the auth service

// ============================================================================
// Core Domain Types
// ============================================================================

/// Core domain types and value objects
pub mod core {
    pub use auth_core::*;
}

// Re-export most commonly used core types at the root level
pub use auth_core::{
    Email, Password, TwoFaAttemptId, TwoFaCode, TwoFaError, User, UserError, ValidatedUser,
};

// ============================================================================
// Repository Traits (Ports)
// ============================================================================

/// Repository trait definitions
pub mod repositories {
    pub use auth_core::{
        BannedTokenStore, BannedTokenStoreError, TwoFaCodeStore, TwoFaCodeStoreError, UserStore,
        UserStoreError,
    };
}

// Re-export repository traits at root level
pub use auth_core::{
    BannedTokenStore, BannedTokenStoreError, EmailClient, TwoFaCodeStore, TwoFaCodeStoreError,
    UserStore, UserStoreError,
};

// ============================================================================
// Use Cases (Application Layer)
// ============================================================================

/// Application use cases
pub mod use_cases {
    pub use auth_application::*;
}

// Re-export use cases at root level
pub use auth_application::{
    ChangePasswordUseCase, DeleteAccountUseCase, ElevateUseCase, LoginUseCase, LogoutUseCase,
    SignupUseCase, Verify2FaUseCase,
};

// ============================================================================
// Adapters (Infrastructure)
// ============================================================================

/// Infrastructure adapters
pub mod adapters {
    /// HTTP route handlers
    pub mod http {
        pub use auth_adapters::http::*;
    }

    /// Persistence implementations
    pub mod persistence {
        pub use auth_adapters::persistence::*;
    }

    /// Email client implementations
    pub mod email {
        pub use auth_adapters::email::*;
    }

    /// JWT authentication utilities
    pub mod auth {
        pub use auth_adapters::auth::*;
    }

    /// Configuration
    pub mod config {
        pub use auth_adapters::config::*;
    }
}

// Re-export commonly used adapters at root level
pub use auth_adapters::{
    email::{MockEmailClient, PostmarkEmailClient},
    persistence::{
        HashMapTwoFaCodeStore, HashMapUserStore, HashSetBannedTokenStore, PostgresUserStore,
        RedisBannedTokenStore, RedisTwoFaCodeStore,
    },
};

// ============================================================================
// Auth Service (Main Entry Point)
// ============================================================================

/// Main auth service
pub use auth_service_lib::{configure_postgresql, configure_redis, get_redis_client, AuthService};

// ============================================================================
// Re-export common external dependencies
// ============================================================================

/// Re-export async-trait for implementing repository traits
pub use async_trait::async_trait;

/// Re-export secrecy for working with secrets
pub use secrecy::{ExposeSecret, Secret};
