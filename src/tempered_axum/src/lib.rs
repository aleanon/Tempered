//! Axum integration for the Tempered authentication library.
//!
//! This crate provides zero-cost Axum adapters for the framework-agnostic
//! authentication library defined in `tempered_core`.
//!
//! # Architecture
//!
//! The scheme's route table (`tempered_adapters::endpoints`) decides which
//! routes exist, where, and behind which check, and serves them. This crate
//! mounts the table on an axum `Router`, converts requests and responses,
//! applies the same checks to your own routers (with `Extension<Claims>`),
//! and serves static files.
//!
//! # Usage
//!
//! ```ignore
//! let app: axum::Router = tempered_axum::auth_service(scheme, "assets".into())
//!     .validated_router(my_routes)
//!     .into();
//! ```

pub mod adapters;
mod assets;
pub mod auth_service;
pub mod error;
pub mod middleware;

// Re-export for convenience
pub use adapters::{AxumRequest, AxumResponseBuilder, response_builder};
pub use auth_service::{AuthService, auth_service};
pub use error::{IntoStatusMessage, status_code};
pub use tempered_adapters::endpoints::{PathOverrides, RouteId, Tier};
