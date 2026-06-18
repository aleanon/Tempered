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
        self.identities
            .write()
            .await
            .insert((provider, subject), email);
        Ok(())
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
}
