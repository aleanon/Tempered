use auth_core::{Email, EmailClient};
use reqwest::{Client, Url};
use secrecy::{ExposeSecret, Secret};

pub struct PostmarkEmailClient {
    http_client: Client,
    base_url: String,
    sender: Email,
    authorization_token: Secret<String>,
}

impl PostmarkEmailClient {
    pub fn new(
        base_url: String,
        sender: Email,
        authorization_token: Secret<String>,
        http_client: Client,
    ) -> Self {
        Self {
            http_client,
            base_url,
            sender,
            authorization_token,
        }
    }
}

#[async_trait::async_trait]
impl EmailClient for PostmarkEmailClient {
    #[tracing::instrument(name = "Sending email", skip_all)]
    async fn send_email(
        &self,
        recipient: &Email,
        subject: &str,
        content: &str,
    ) -> Result<(), String> {
        let base = Url::parse(&self.base_url).map_err(|e| e.to_string())?;
        let url = base.join("/email").map_err(|e| e.to_string())?;

        let request_body = SendEmailRequest {
            from: self.sender.as_ref().expose_secret(),
            to: recipient.as_ref().expose_secret(),
            subject,
            html_body: content,
            text_body: content,
            message_stream: MESSAGE_STREAM,
        };

        let request = self
            .http_client
            .post(url)
            .header(
                POSTMARK_AUTH_HEADER,
                self.authorization_token.expose_secret(),
            )
            .json(&request_body);

        request
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}

const MESSAGE_STREAM: &str = "outbound";
const POSTMARK_AUTH_HEADER: &str = "X-Postmark-Server-Token";

#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct SendEmailRequest<'a> {
    from: &'a str,
    to: &'a str,
    subject: &'a str,
    html_body: &'a str,
    text_body: &'a str,
    message_stream: &'a str,
}
