use async_trait::async_trait;

use crate::domain::email::Email;

/// Port trait for email sending service
#[async_trait]
pub trait EmailClient: Send + Sync {
    async fn send_email(
        &self,
        recipient: &Email,
        subject: &str,
        content: &str,
    ) -> Result<(), String>;
}
