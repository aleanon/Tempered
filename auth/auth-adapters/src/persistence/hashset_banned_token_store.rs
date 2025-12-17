use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

use auth_core::{BannedTokenStore, BannedTokenStoreError};

#[derive(Debug, Default, Clone)]
pub struct HashSetBannedTokenStore {
    banned_tokens: Arc<RwLock<HashSet<String>>>,
}

impl HashSetBannedTokenStore {
    pub fn new() -> Self {
        Self {
            banned_tokens: Arc::new(RwLock::new(HashSet::new())),
        }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for HashSetBannedTokenStore {
    async fn ban_token(&self, token: String) -> Result<(), BannedTokenStoreError> {
        let mut banned_tokens = self.banned_tokens.write().await;
        banned_tokens.insert(token);
        Ok(())
    }

    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        let banned_tokens = self.banned_tokens.read().await;
        Ok(banned_tokens.contains(token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ban_token() {
        let store = HashSetBannedTokenStore::new();
        assert!(store.contains_token("token1").await.is_ok());
    }

    #[tokio::test]
    async fn test_token_is_banned() {
        let store = HashSetBannedTokenStore::new();
        store.ban_token("token1".to_string()).await.unwrap();
        assert!(store.contains_token("token1").await.unwrap());
    }

    #[tokio::test]
    async fn test_token_is_not_banned() {
        let store = HashSetBannedTokenStore::new();
        assert!(!store.contains_token("token2").await.unwrap());
    }
}
