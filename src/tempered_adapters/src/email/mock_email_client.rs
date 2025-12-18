use tempered_core::{Email, EmailClient};

#[derive(Debug, Clone, Default)]
pub struct MockEmailClient;

impl MockEmailClient {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl EmailClient for MockEmailClient {
    async fn send_email(
        &self,
        _recipient: &Email,
        _subject: &str,
        _content: &str,
    ) -> Result<(), String> {
        Ok(())
    }
}
