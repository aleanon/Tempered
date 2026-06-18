use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use tempered_core::{ChallengeStore, ChallengeStoreError, Email, WebAuthnChallenge};

/// In-memory single-use WebAuthn challenge store for tests.
#[derive(Default, Clone)]
pub struct HashMapChallengeStore {
    challenges: Arc<RwLock<HashMap<WebAuthnChallenge, Option<Email>>>>,
}

impl HashMapChallengeStore {
    pub fn new() -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl ChallengeStore for HashMapChallengeStore {
    async fn store_challenge(
        &self,
        challenge: WebAuthnChallenge,
        email: Option<Email>,
    ) -> Result<(), ChallengeStoreError> {
        self.challenges.write().await.insert(challenge, email);
        Ok(())
    }

    async fn consume_challenge(
        &self,
        challenge: &WebAuthnChallenge,
    ) -> Result<Option<Email>, ChallengeStoreError> {
        self.challenges
            .write()
            .await
            .remove(challenge)
            .ok_or(ChallengeStoreError::ChallengeNotFound)
    }
}
