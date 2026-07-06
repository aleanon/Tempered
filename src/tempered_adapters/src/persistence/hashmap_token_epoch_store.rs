use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use tempered_core::{Email, TokenEpochStore, TokenEpochStoreError};

/// In-memory [`TokenEpochStore`] backed by a `HashMap`.
///
/// # Warning: development and tests only
///
/// Cutoffs are per-process and lost on restart — after a restart, tokens
/// revoked by a password change validate again. Use
/// [`RedisTokenEpochStore`](super::redis_token_epoch_store::RedisTokenEpochStore)
/// in production.
#[derive(Default, Clone)]
pub struct HashMapTokenEpochStore {
    cutoffs: Arc<RwLock<HashMap<Email, i64>>>,
}

impl HashMapTokenEpochStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl TokenEpochStore for HashMapTokenEpochStore {
    async fn min_valid_iat(&self, email: &Email) -> Result<Option<i64>, TokenEpochStoreError> {
        Ok(self.cutoffs.read().await.get(email).copied())
    }

    async fn revoke_before(
        &self,
        email: &Email,
        cutoff: i64,
    ) -> Result<(), TokenEpochStoreError> {
        let mut cutoffs = self.cutoffs.write().await;
        let entry = cutoffs.entry(email.clone()).or_insert(cutoff);
        // Never lower an existing cutoff (contract).
        *entry = (*entry).max(cutoff);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use secrecy::Secret;

    use super::*;

    fn email() -> Email {
        Email::try_from(Secret::new("test@example.com".to_string())).unwrap()
    }

    #[tokio::test]
    async fn no_cutoff_until_revoked() {
        let store = HashMapTokenEpochStore::new();
        assert_eq!(store.min_valid_iat(&email()).await.unwrap(), None);

        store.revoke_before(&email(), 1000).await.unwrap();
        assert_eq!(store.min_valid_iat(&email()).await.unwrap(), Some(1000));
    }

    #[tokio::test]
    async fn cutoff_never_moves_backwards() {
        let store = HashMapTokenEpochStore::new();
        store.revoke_before(&email(), 2000).await.unwrap();
        store.revoke_before(&email(), 1000).await.unwrap();
        assert_eq!(store.min_valid_iat(&email()).await.unwrap(), Some(2000));
    }
}
