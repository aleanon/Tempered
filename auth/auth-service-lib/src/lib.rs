mod auth_service;
mod helpers;
mod tracing;

pub use auth_service::AuthService;
pub use helpers::{configure_postgresql, configure_redis, get_redis_client};

// Re-export commonly used types
pub use auth_core::{BannedTokenStore, Email, EmailClient, TwoFaCodeStore, UserStore};
