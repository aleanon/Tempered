use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use tempered_core::{
    Email, PasswordResetToken, PasswordResetTokenStore, PasswordResetTokenStoreError,
};

#[derive(Default, Clone)]
pub struct HashMapPasswordResetTokenStore {
    tokens: Arc<RwLock<HashMap<PasswordResetToken, Email>>>,
}

impl HashMapPasswordResetTokenStore {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl PasswordResetTokenStore for HashMapPasswordResetTokenStore {
    async fn store_token(
        &self,
        token: PasswordResetToken,
        email: Email,
    ) -> Result<(), PasswordResetTokenStoreError> {
        self.tokens.write().await.insert(token, email);
        Ok(())
    }

    async fn get_email_for_token(
        &self,
        token: &PasswordResetToken,
    ) -> Result<Email, PasswordResetTokenStoreError> {
        self.tokens
            .read()
            .await
            .get(token)
            .cloned()
            .ok_or(PasswordResetTokenStoreError::TokenNotFound)
    }

    async fn delete_token(
        &self,
        token: &PasswordResetToken,
    ) -> Result<(), PasswordResetTokenStoreError> {
        self.tokens
            .write()
            .await
            .remove(token)
            .ok_or(PasswordResetTokenStoreError::TokenNotFound)?;
        Ok(())
    }
}
