use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use secrecy::Secret;
use tempered_core::{OAuthStateStore, OAuthStateStoreError};

/// In-memory single-use OAuth `state` store for tests and local development.
///
/// Dev/test only: entries never expire, so abandoned flows accumulate.
#[derive(Default, Clone)]
pub struct HashMapOAuthStateStore {
    /// Pending `state` -> the PKCE verifier generated with it.
    states: Arc<RwLock<HashMap<String, Secret<String>>>>,
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
        code_verifier: Secret<String>,
    ) -> Result<(), OAuthStateStoreError> {
        self.states.write().await.insert(state, code_verifier);
        Ok(())
    }

    async fn consume_state(&self, state: &str) -> Result<Secret<String>, OAuthStateStoreError> {
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
    use secrecy::ExposeSecret;

    #[tokio::test]
    async fn consume_returns_the_verifier_exactly_once() {
        let store = HashMapOAuthStateStore::new();
        store
            .store_state("s1".to_string(), Secret::new("verifier-1".to_string()))
            .await
            .unwrap();

        let verifier = store.consume_state("s1").await.unwrap();
        assert_eq!(verifier.expose_secret(), "verifier-1");
        assert!(matches!(
            store.consume_state("s1").await,
            Err(OAuthStateStoreError::UnknownState)
        ));
    }

    #[tokio::test]
    async fn unknown_state_is_rejected() {
        let store = HashMapOAuthStateStore::new();
        assert!(matches!(
            store.consume_state("never-stored").await,
            Err(OAuthStateStoreError::UnknownState)
        ));
    }
}
