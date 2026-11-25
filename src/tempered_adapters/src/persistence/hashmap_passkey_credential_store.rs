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
        use std::collections::hash_map::Entry;
        match self
            .credentials
            .write()
            .await
            .entry(cred.credential_id.clone())
        {
            // Never overwrite: that would hand the credential to a new owner.
            Entry::Occupied(_) => Err(PasskeyStoreError::CredentialAlreadyExists),
            Entry::Vacant(slot) => {
                slot.insert(cred);
                Ok(())
            }
        }
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

    async fn update_after_authentication(
        &self,
        id: &CredentialId,
        new_sign_count: u32,
        credential_data: Option<Vec<u8>>,
    ) -> Result<(), PasskeyStoreError> {
        let mut map = self.credentials.write().await;
        let cred = map
            .get_mut(id)
            .ok_or(PasskeyStoreError::CredentialNotFound)?;
        // Checked under the same write lock as the update (the port's
        // contract).
        let advances =
            new_sign_count > cred.sign_count || (new_sign_count == 0 && cred.sign_count == 0);
        if !advances {
            return Err(PasskeyStoreError::SignCountNotAdvanced);
        }
        cred.sign_count = new_sign_count;
        if let Some(data) = credential_data {
            cred.credential_data = data;
        }
        Ok(())
    }

    async fn delete_all_for_user(&self, owner: &Email) -> Result<(), PasskeyStoreError> {
        self.credentials
            .write()
            .await
            .retain(|_, cred| &cred.owner != owner);
        Ok(())
    }

    async fn delete_credential(
        &self,
        owner: &Email,
        id: &CredentialId,
    ) -> Result<bool, PasskeyStoreError> {
        let mut credentials = self.credentials.write().await;
        if credentials.get(id).is_some_and(|c| &c.owner == owner) {
            credentials.remove(id);
            return Ok(true);
        }
        Ok(false)
    }

    async fn rename_credential(
        &self,
        owner: &Email,
        id: &CredentialId,
        name: Option<String>,
    ) -> Result<bool, PasskeyStoreError> {
        match self.credentials.write().await.get_mut(id) {
            Some(cred) if &cred.owner == owner => {
                cred.name = name;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn reassign(&self, old: &Email, new: &Email) -> Result<(), PasskeyStoreError> {
        for cred in self.credentials.write().await.values_mut() {
            if &cred.owner == old {
                cred.owner = new.clone();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn meets_the_passkey_credential_store_contract() {
        crate::persistence::contract::passkey_credential_store(HashMapPasskeyCredentialStore::new()).await;
    }
}
