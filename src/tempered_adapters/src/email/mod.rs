pub mod mock_email_client;
#[cfg(feature = "postmark-email")]
pub mod postmark_email_client;

pub use mock_email_client::MockEmailClient;
#[cfg(feature = "postmark-email")]
pub use postmark_email_client::PostmarkEmailClient;
