use tempered_core::{BannedTokenStore, BannedTokenStoreError};

/// Error types for logout use case
#[derive(Debug, thiserror::Error)]
pub enum LogoutError {
    #[error("Banned token store error: {0}")]
    BannedTokenStoreError(#[from] BannedTokenStoreError),
}

/// Logout use case - invalidates JWT tokens
pub struct LogoutUseCase<B>
where
    B: BannedTokenStore,
{
    banned_token_store: B,
}

impl<B> LogoutUseCase<B>
where
    B: BannedTokenStore,
{
    pub fn new(banned_token_store: B) -> Self {
        Self { banned_token_store }
    }

    /// Execute the logout use case
    ///
    /// # Arguments
    /// * `token` - The JWT token to invalidate
    /// * `elevated_token` - Optional elevated JWT token to also invalidate
    ///
    /// # Returns
    /// Ok(()) on success, or LogoutError
    #[tracing::instrument(name = "LogoutUseCase::execute", skip(self, token, elevated_token))]
    pub async fn execute(
        &self,
        token: String,
        elevated_token: Option<String>,
    ) -> Result<(), LogoutError> {
        // Ban the main token
        self.banned_token_store.ban_token(token).await?;

        // Ban elevated token if present
        if let Some(elevated) = elevated_token {
            self.banned_token_store.ban_token(elevated).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::RwLock;

    use super::*;
    use std::{collections::HashSet, sync::Arc};

    #[derive(Clone)]
    struct MockBannedTokenStore {
        banned_tokens: Arc<RwLock<HashSet<String>>>,
    }

    #[async_trait::async_trait]
    impl BannedTokenStore for MockBannedTokenStore {
        async fn ban_token(&self, token: String) -> Result<(), BannedTokenStoreError> {
            self.banned_tokens.write().await.insert(token);
            Ok(())
        }

        async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
            Ok(self.banned_tokens.read().await.contains(token))
        }
    }

    #[tokio::test]
    async fn test_logout_single_token() {
        let store = MockBannedTokenStore {
            banned_tokens: Arc::new(RwLock::new(HashSet::new())),
        };

        let use_case = LogoutUseCase::new(store.clone());
        let token = "test_token".to_string();

        let result = use_case.execute(token.clone(), None).await;
        assert!(result.is_ok());

        // Verify token was banned
        let is_banned = store.contains_token(&token).await.unwrap();
        assert!(is_banned);
    }

    #[tokio::test]
    async fn test_logout_with_elevated_token() {
        let store = MockBannedTokenStore {
            banned_tokens: Arc::new(RwLock::new(HashSet::new())),
        };

        let use_case = LogoutUseCase::new(store.clone());
        let token = "test_token".to_string();
        let elevated_token = "elevated_token".to_string();

        let result = use_case
            .execute(token.clone(), Some(elevated_token.clone()))
            .await;
        assert!(result.is_ok());

        // Verify both tokens were banned
        assert!(store.contains_token(&token).await.unwrap());
        assert!(store.contains_token(&elevated_token).await.unwrap());
    }
}
