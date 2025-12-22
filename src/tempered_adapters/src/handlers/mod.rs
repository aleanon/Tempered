//! Framework-agnostic authentication handlers.
//!
//! These handlers contain the pure authentication logic without any framework dependencies.
//! Framework-specific routes (Axum, Actix, etc.) extract data from requests, call these handlers,
//! and convert the results back to framework responses.

pub mod change_password;
pub mod delete_account;
pub mod elevate;
pub mod login;
pub mod logout;
pub mod signup;
pub mod verify_2fa;
pub mod verify_elevated_token;
pub mod verify_token;

pub use change_password::handle_change_password;
pub use delete_account::handle_delete_account;
pub use elevate::handle_elevate;
pub use login::handle_login;
pub use logout::handle_logout;
pub use signup::handle_signup;
pub use verify_2fa::handle_verify_2fa;
pub use verify_elevated_token::handle_verify_elevated_token;
pub use verify_token::handle_verify_token;
