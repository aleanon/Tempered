use std::sync::Arc;

use redis::Commands;
use secrecy::ExposeSecret;
use tokio::sync::RwLock;

use tempered_core::{
    Email, PasswordResetToken, PasswordResetTokenStore, PasswordResetTokenStoreError,
};

const ONE_HOUR_IN_SECONDS: u64 = 3600;
const RESET_TOKEN_PREFIX: &str = "password_reset:";

#[derive(Clone)]
pub struct RedisPasswordResetTokenStore {
    client: Arc<RwLock<redis::Connection>>,
}

impl RedisPasswordResetTokenStore {
    pub fn new(client: Arc<RwLock<redis::Connection>>) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl PasswordResetTokenStore for RedisPasswordResetTokenStore {
    async fn store_token(
        &self,
        token: PasswordResetToken,
        email: Email,
    ) -> Result<(), PasswordResetTokenStoreError> {
        let key = get_key(&token);
        let value = email.as_ref().expose_secret().clone();

        self.client
            .write()
            .await
            .set_ex(key, value, ONE_HOUR_IN_SECONDS)
            .map_err(|e| PasswordResetTokenStoreError::UnexpectedError(e.to_string()))
    }

    async fn get_email_for_token(
        &self,
        token: &PasswordResetToken,
    ) -> Result<Email, PasswordResetTokenStoreError> {
        let key = get_key(token);

        let email_str: String = self
            .client
            .write()
            .await
            .get(key)
            .map_err(|_| PasswordResetTokenStoreError::TokenNotFound)?;

        Email::try_from(secrecy::Secret::new(email_str))
            .map_err(|e| PasswordResetTokenStoreError::UnexpectedError(e.to_string()))
    }

    async fn delete_token(
        &self,
        token: &PasswordResetToken,
    ) -> Result<(), PasswordResetTokenStoreError> {
        let key = get_key(token);

        self.client
            .write()
            .await
            .del(key)
            .map_err(|_| PasswordResetTokenStoreError::TokenNotFound)
    }
}

fn get_key(token: &PasswordResetToken) -> String {
    format!("{}{}", RESET_TOKEN_PREFIX, token)
}
