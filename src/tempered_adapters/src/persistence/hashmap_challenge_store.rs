use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use tempered_core::{CeremonyId, ChallengeStore, ChallengeStoreError, Email, PendingCeremony};

/// In-memory single-use store for in-flight WebAuthn ceremonies.
///
/// Dev/test only: entries never expire, so abandoned ceremonies accumulate.
#[derive(Default, Clone)]
pub struct HashMapChallengeStore {
    ceremonies: Arc<RwLock<HashMap<CeremonyId, PendingCeremony>>>,
}

impl HashMapChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl ChallengeStore for HashMapChallengeStore {
    async fn store_ceremony(
        &self,
        id: CeremonyId,
        ceremony: PendingCeremony,
    ) -> Result<(), ChallengeStoreError> {
        self.ceremonies.write().await.insert(id, ceremony);
        Ok(())
    }

    async fn consume_ceremony(
        &self,
        id: &CeremonyId,
    ) -> Result<PendingCeremony, ChallengeStoreError> {
        self.ceremonies
            .write()
            .await
            .remove(id)
            .ok_or(ChallengeStoreError::ChallengeNotFound)
    }

    async fn delete_all_for_user(&self, user: &Email) -> Result<(), ChallengeStoreError> {
        self.ceremonies
            .write()
            .await
            .retain(|_, ceremony| ceremony.user.as_ref() != Some(user));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn meets_the_challenge_store_contract() {
        crate::persistence::contract::challenge_store(HashMapChallengeStore::new()).await;
    }
}
