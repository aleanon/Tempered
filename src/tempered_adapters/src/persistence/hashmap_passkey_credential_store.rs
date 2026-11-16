use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use tempered_core::{
    CredentialId, Email, PasskeyCredential, PasskeyCredentialStore, PasskeyStoreError,
};

/// In-memory passkey credential store for tests and local development.
#[derive(Default, Clone)]
pub struct HashMapPasskeyCredentialStore {
    credentials: Arc<RwLock<HashMap<CredentialId, PasskeyCredential>>>,
}

impl HashMapPasskeyCredentialStore {
    pub fn new() -> Self {
        Self {
            credentials: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl PasskeyCredentialStore for HashMapPasskeyCredentialStore {
    async fn add_credential(&self, cred: PasskeyCredential) -> Result<(), PasskeyStoreError> {
        self.credentials
            .write()
            .await
            .insert(cred.credential_id.clone(), cred);
        Ok(())
    }

    async fn get_credential(
        &self,
        id: &CredentialId,
    ) -> Result<PasskeyCredential, PasskeyStoreError> {
        self.credentials
            .read()
            .await
            .get(id)
            .cloned()
            .ok_or(PasskeyStoreError::CredentialNotFound)
    }

    async fn list_for_user(
        &self,
        owner: &Email,
    ) -> Result<Vec<PasskeyCredential>, PasskeyStoreError> {
        Ok(self
            .credentials
            .read()
            .await
            .values()
            .filter(|c| &c.owner == owner)
            .cloned()
            .collect())
    }

    async fn update_sign_count(
        &self,
        id: &CredentialId,
        new_count: u32,
    ) -> Result<(), PasskeyStoreError> {
        let mut map = self.credentials.write().await;
        let cred = map
            .get_mut(id)
            .ok_or(PasskeyStoreError::CredentialNotFound)?;
        cred.sign_count = new_count;
        Ok(())
    }
}
