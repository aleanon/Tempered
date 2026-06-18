use async_trait::async_trait;
use thiserror::Error;

use crate::domain::{
    email::Email,
    oauth::{OAuthProviderConfig, OAuthUserInfo},
};

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

#[derive(Debug, Error)]
pub enum OAuthHttpError {
    #[error("Token exchange failed: {0}")]
    TokenExchange(String),
    #[error("Userinfo request failed: {0}")]
    UserInfo(String),
}

/// Port for the outbound HTTP calls an OAuth2 flow makes to a provider.
///
/// Abstracted as a trait so the flow can be unit-tested with a mock client
/// (no network) while production uses a real `reqwest`-backed implementation.
#[async_trait]
pub trait OAuthHttpClient: Send + Sync {
    /// Exchange an authorization `code` for an access token.
    async fn exchange_code(
        &self,
        config: &OAuthProviderConfig,
        code: &str,
    ) -> Result<String, OAuthHttpError>;

    /// Fetch the user's identity using the access token.
    async fn fetch_user_info(
        &self,
        config: &OAuthProviderConfig,
        access_token: &str,
    ) -> Result<OAuthUserInfo, OAuthHttpError>;
}
