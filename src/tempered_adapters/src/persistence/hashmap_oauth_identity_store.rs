use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use tempered_core::{OAuthIdentityStore, OAuthIdentityStoreError, UserId};

/// In-memory `(provider, subject) -> account` identity map for tests.
#[derive(Default, Clone)]
pub struct HashMapOAuthIdentityStore {
    identities: Arc<RwLock<HashMap<(String, String), UserId>>>,
}

impl HashMapOAuthIdentityStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl OAuthIdentityStore for HashMapOAuthIdentityStore {
    async fn link_identity(
        &self,
        provider: String,
        subject: String,
        user: UserId,
    ) -> Result<(), OAuthIdentityStoreError> {
        let mut identities = self.identities.write().await;
        let key = (provider, subject);
        match identities.get(&key) {
            // Re-linking the same identity to the same account is idempotent.
            Some(existing) if existing == &user => Ok(()),
            // Refuse to silently move an existing identity to another account.
            Some(_) => Err(OAuthIdentityStoreError::AlreadyLinked),
            None => {
                identities.insert(key, user);
                Ok(())
            }
        }
    }

    async fn find_user(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<UserId>, OAuthIdentityStoreError> {
        let identities = self.identities.read().await;
        Ok(identities
            .get(&(provider.to_string(), subject.to_string()))
            .copied())
    }

    async fn has_identity_for_user(&self, user: &UserId) -> Result<bool, OAuthIdentityStoreError> {
        Ok(self.identities.read().await.values().any(|u| u == user))
    }

    async fn list_for_user(
        &self,
        user: &UserId,
    ) -> Result<Vec<(String, String)>, OAuthIdentityStoreError> {
        let mut linked: Vec<(String, String)> = self
            .identities
            .read()
            .await
            .iter()
            .filter(|(_, u)| *u == user)
            .map(|(key, _)| key.clone())
            .collect();
        linked.sort();
        Ok(linked)
    }

    async fn unlink(&self, user: &UserId, provider: &str) -> Result<bool, OAuthIdentityStoreError> {
        let mut identities = self.identities.write().await;
        let before = identities.len();
        identities.retain(|(p, _), u| !(p == provider && u == user));
        Ok(identities.len() < before)
    }

    async fn unlink_all_for_user(&self, user: &UserId) -> Result<(), OAuthIdentityStoreError> {
        self.identities.write().await.retain(|_, u| u != user);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn meets_the_oauth_identity_store_contract() {
        crate::persistence::contract::oauth_identity_store(
            HashMapOAuthIdentityStore::new(),
            [UserId::new(), UserId::new()],
        )
        .await;
    }
}
