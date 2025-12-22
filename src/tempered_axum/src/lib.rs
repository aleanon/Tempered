//! Axum integration for the Tempered authentication library.
//!
//! This crate provides zero-cost Axum adapters for the framework-agnostic
//! authentication library defined in `tempered_core`.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────┐
//! │  tempered_core: HTTP trait definitions   │
//! └──────────────┬───────────────────────────┘
//!                │
//!                ▼
//! ┌──────────────────────────────────────────┐
//! │  tempered_axum: Axum implementations     │
//! │  - AxumRequest newtype wrapper           │
//! │  - AxumResponseBuilder                   │
//! │  - Axum route handlers                   │
//! └──────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use tempered_axum::{routes, response_builder};
//! use tempered_adapters::authentication::JwtScheme;
//!
//! let app = Router::new()
//!     .route("/login", post(routes::login::<JwtScheme>))
//!     .route("/logout", post(routes::logout::<JwtScheme>))
//!     .with_state(jwt_scheme);
//! ```

pub mod adapters;
pub mod routes;

// Re-export for convenience
pub use adapters::{AxumRequest, AxumResponseBuilder, response_builder};
