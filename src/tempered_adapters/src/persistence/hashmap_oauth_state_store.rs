use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

use tempered_core::{OAuthStateStore, OAuthStateStoreError};

/// In-memory single-use OAuth `state` store for tests and local development.
#[derive(Default, Clone)]
pub struct HashMapOAuthStateStore {
    states: Arc<RwLock<HashSet<String>>>,
}

impl HashMapOAuthStateStore {
    pub fn new() -> Self {
        Self {
            states: Arc::new(RwLock::new(HashSet::new())),
        }
    }
}

#[async_trait::async_trait]
impl OAuthStateStore for HashMapOAuthStateStore {
    async fn store_state(&self, state: String) -> Result<(), OAuthStateStoreError> {
        self.states.write().await.insert(state);
        Ok(())
    }

    async fn consume_state(&self, state: &str) -> Result<(), OAuthStateStoreError> {
        if self.states.write().await.remove(state) {
            Ok(())
        } else {
            Err(OAuthStateStoreError::UnknownState)
        }
    }
}
