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
}
