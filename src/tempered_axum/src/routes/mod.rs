//! Axum-specific route handlers.
//!
//! These routes are Axum-specific - they use Axum's extractors to get data from requests,
//! call the framework-agnostic handlers, and convert results to Axum responses.

pub mod change_password;
pub mod delete_account;
pub mod elevate;
pub mod login;
pub mod logout;
pub mod signup;
pub mod verify_2fa;
pub mod verify_elevated_token;
pub mod verify_token;

pub use change_password::change_password;
pub use delete_account::delete_account;
pub use elevate::elevate;
pub use login::login;
pub use logout::logout;
pub use signup::signup;
pub use verify_2fa::verify_2fa;
pub use verify_elevated_token::verify_elevated_token;
pub use verify_token::verify_token;
