use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use tempered_core::{
    Email, PasswordResetToken, PasswordResetTokenStore, PasswordResetTokenStoreError,
};

/// In-memory [`PasswordResetTokenStore`] backed by a `HashMap`.
///
/// # Warning: development and tests only
///
/// This store applies **no expiry** — a reset token stays valid until it is
/// consumed or the process restarts. Use
/// [`RedisPasswordResetTokenStore`](super::redis_password_reset_token_store::RedisPasswordResetTokenStore),
/// which sets a TTL, in production.
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

    async fn consume_token(
        &self,
        token: &PasswordResetToken,
    ) -> Result<Email, PasswordResetTokenStoreError> {
        // remove() under the write lock is the atomic get-and-delete: the
        // second concurrent consumer finds nothing.
        self.tokens
            .write()
            .await
            .remove(token)
            .ok_or(PasswordResetTokenStoreError::TokenNotFound)
    }
}
