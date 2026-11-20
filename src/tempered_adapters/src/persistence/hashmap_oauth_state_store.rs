use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use tempered_core::{OAuthStateStore, OAuthStateStoreError, PendingAuthorization};

/// In-memory single-use OAuth `state` store for tests and local development.
///
/// Dev/test only: entries never expire, so abandoned flows accumulate.
#[derive(Default, Clone)]
pub struct HashMapOAuthStateStore {
    /// `state` -> the authorization request awaiting its callback.
    states: Arc<RwLock<HashMap<String, PendingAuthorization>>>,
}

impl HashMapOAuthStateStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl OAuthStateStore for HashMapOAuthStateStore {
    async fn store_state(
        &self,
        state: String,
        pending: PendingAuthorization,
    ) -> Result<(), OAuthStateStoreError> {
        self.states.write().await.insert(state, pending);
        Ok(())
    }

    async fn consume_state(
        &self,
        state: &str,
    ) -> Result<PendingAuthorization, OAuthStateStoreError> {
        self.states
            .write()
            .await
            .remove(state)
            .ok_or(OAuthStateStoreError::UnknownState)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn meets_the_oauth_state_store_contract() {
        crate::persistence::contract::oauth_state_store(HashMapOAuthStateStore::new()).await;
    }
}
