use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use tempered_core::{ApiKeyId, ApiKeyMetadata, ApiKeyRecord, ApiKeyStore, ApiKeyStoreError, Email};

/// In-memory API key store for tests and local development.
///
/// Keyed by the non-secret `prefix` so validation is an O(1) lookup. Only the
/// SHA-256 hash of the secret is held (inside the `ApiKeyRecord`).
#[derive(Default, Clone)]
pub struct HashMapApiKeyStore {
    by_prefix: Arc<RwLock<HashMap<String, ApiKeyRecord>>>,
}

impl HashMapApiKeyStore {
    pub fn new() -> Self {
        Self {
            by_prefix: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl ApiKeyStore for HashMapApiKeyStore {
    async fn create_key(&self, record: ApiKeyRecord) -> Result<(), ApiKeyStoreError> {
        let mut map = self.by_prefix.write().await;
        if map.contains_key(&record.prefix) {
            return Err(ApiKeyStoreError::PrefixTaken);
        }
        map.insert(record.prefix.clone(), record);
        Ok(())
    }

    async fn find_by_prefix(&self, prefix: &str) -> Result<ApiKeyRecord, ApiKeyStoreError> {
        self.by_prefix
            .read()
            .await
            .get(prefix)
            .cloned()
            .ok_or(ApiKeyStoreError::NotFound)
    }

    async fn revoke_key(&self, owner: &Email, id: &ApiKeyId) -> Result<(), ApiKeyStoreError> {
        let mut map = self.by_prefix.write().await;
        let prefix = map
            .iter()
            .find(|(_, r)| &r.id == id && &r.owner == owner)
            .map(|(p, _)| p.clone());
        match prefix {
            Some(p) => {
                map.remove(&p);
                Ok(())
            }
            None => Err(ApiKeyStoreError::NotFound),
        }
    }

    async fn list_for_user(&self, owner: &Email) -> Result<Vec<ApiKeyMetadata>, ApiKeyStoreError> {
        let map = self.by_prefix.read().await;
        Ok(map
            .values()
            .filter(|r| &r.owner == owner)
            .map(|r| ApiKeyMetadata {
                id: r.id.clone(),
                prefix: r.prefix.clone(),
                scopes: r.scopes.clone(),
                created_at: r.created_at,
                expires_at: r.expires_at,
                last_used_at: r.last_used_at,
            })
            .collect())
    }

    async fn record_use(&self, id: &ApiKeyId, at: u64) -> Result<(), ApiKeyStoreError> {
        if let Some(record) = self
            .by_prefix
            .write()
            .await
            .values_mut()
            .find(|r| &r.id == id)
        {
            record.last_used_at = Some(at);
        }
        Ok(())
    }

    async fn delete_all_for_owner(&self, owner: &Email) -> Result<(), ApiKeyStoreError> {
        self.by_prefix
            .write()
            .await
            .retain(|_, r| &r.owner != owner);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn meets_the_api_key_store_contract() {
        crate::persistence::contract::api_key_store(HashMapApiKeyStore::new()).await;
    }
}
