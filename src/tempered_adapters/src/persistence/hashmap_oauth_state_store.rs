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
    use secrecy::{ExposeSecret, Secret};

    fn pending(provider: &str, verifier: &str) -> PendingAuthorization {
        PendingAuthorization {
            provider: provider.to_string(),
            code_verifier: Secret::new(verifier.to_string()),
        }
    }

    #[tokio::test]
    async fn consume_returns_the_pending_request_exactly_once() {
        let store = HashMapOAuthStateStore::new();
        store
            .store_state("s1".to_string(), pending("google", "verifier-1"))
            .await
            .unwrap();

        let found = store.consume_state("s1").await.unwrap();
        assert_eq!(found.provider, "google");
        assert_eq!(found.code_verifier.expose_secret(), "verifier-1");
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
