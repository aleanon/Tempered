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
    pub use tempered_core::*;
}

// Re-export most commonly used core types at the root level
pub use tempered_core::{
    Email, EmailVerificationToken, Password, TwoFaAttemptId, TwoFaCode, TwoFaError, User,
    UserError, ValidatedUser,
};

// ============================================================================
// Repository Traits (Ports)
// ============================================================================

/// Repository trait definitions
pub mod repositories {
    pub use tempered_core::{
        BannedTokenStore, BannedTokenStoreError, TwoFaCodeStore, TwoFaCodeStoreError, UserStore,
        UserStoreError,
    };
}

// Re-export repository traits at root level
pub use core::{
    BannedTokenStore, BannedTokenStoreError, EmailClient, EmailVerificationStoreError,
    EmailVerificationTokenStore, RequiresEmailVerification, TwoFaCodeStore, TwoFaCodeStoreError,
    UserStore, UserStoreError,
};

// ============================================================================
// Adapters (Infrastructure)
// ============================================================================

/// Infrastructure adapters
pub mod adapters {

    /// Persistence implementations
    pub mod persistence {
        pub use tempered_adapters::persistence::*;
    }

    /// Email client implementations
    pub mod email {
        pub use tempered_adapters::email::*;
    }

    /// JWT authentication utilities
    pub mod auth {
        pub use tempered_adapters::auth_validation::*;
    }
}

// Re-export commonly used adapters at root level
pub use tempered_adapters::{
    auth_validation::local_jwt_validator::JwtAuthConfig,
    authentication::jwt_scheme::JwtScheme,
    email::{MockEmailClient, PostmarkEmailClient},
    persistence::{
        HashMapEmailVerificationTokenStore, HashMapPasswordResetTokenStore, HashMapTwoFaCodeStore,
        HashMapUserStore, HashSetBannedTokenStore, PostgresUserStore, RedisBannedTokenStore,
        RedisPasswordResetTokenStore, RedisTwoFaCodeStore,
    },
};

// ============================================================================
// Re-export common external dependencies
// ============================================================================

/// Re-export async-trait for implementing repository traits
pub use async_trait::async_trait;

/// Re-export secrecy for working with secrets
pub use secrecy::{ExposeSecret, Secret};

pub use http;
