use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use tempered_core::{Email, OAuthIdentityStore, OAuthIdentityStoreError};

/// In-memory `(provider, subject) -> Email` identity map for tests.
#[derive(Default, Clone)]
pub struct HashMapOAuthIdentityStore {
    identities: Arc<RwLock<HashMap<(String, String), Email>>>,
}

impl HashMapOAuthIdentityStore {
    pub fn new() -> Self {
        Self {
            identities: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl OAuthIdentityStore for HashMapOAuthIdentityStore {
    async fn link_identity(
        &self,
        provider: String,
        subject: String,
        email: Email,
    ) -> Result<(), OAuthIdentityStoreError> {
        let mut identities = self.identities.write().await;
        let key = (provider, subject);
        match identities.get(&key) {
            // Re-linking the same identity to the same email is idempotent.
            Some(existing) if existing == &email => Ok(()),
            // Refuse to silently move an existing identity to another account.
            Some(_) => Err(OAuthIdentityStoreError::AlreadyLinked),
            None => {
                identities.insert(key, email);
                Ok(())
            }
        }
    }

    async fn find_email(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<Email>, OAuthIdentityStoreError> {
        Ok(self
            .identities
            .read()
            .await
            .get(&(provider.to_string(), subject.to_string()))
            .cloned())
    }

    async fn has_identity_for_email(&self, email: &Email) -> Result<bool, OAuthIdentityStoreError> {
        Ok(self.identities.read().await.values().any(|e| e == email))
    }

    async fn unlink_all_for_email(&self, email: &Email) -> Result<(), OAuthIdentityStoreError> {
        self.identities.write().await.retain(|_, e| e != email);
        Ok(())
    }

    async fn list_for_user(
        &self,
        email: &Email,
    ) -> Result<Vec<(String, String)>, OAuthIdentityStoreError> {
        let mut links: Vec<(String, String)> = self
            .identities
            .read()
            .await
            .iter()
            .filter(|(_, e)| *e == email)
            .map(|(key, _)| key.clone())
            .collect();
        links.sort();
        Ok(links)
    }

    async fn unlink(&self, email: &Email, provider: &str) -> Result<bool, OAuthIdentityStoreError> {
        let mut identities = self.identities.write().await;
        let before = identities.len();
        identities.retain(|(p, _), e| !(p == provider && e == email));
        Ok(identities.len() != before)
    }

    async fn reassign(&self, old: &Email, new: &Email) -> Result<(), OAuthIdentityStoreError> {
        for email in self.identities.write().await.values_mut() {
            if email == old {
                *email = new.clone();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn meets_the_oauth_identity_store_contract() {
        crate::persistence::contract::oauth_identity_store(HashMapOAuthIdentityStore::new()).await;
    }
}
