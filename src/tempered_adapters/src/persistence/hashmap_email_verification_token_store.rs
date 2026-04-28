use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

use tempered_core::{
    Email, EmailVerificationStoreError, EmailVerificationToken, EmailVerificationTokenStore,
};

/// In-memory email verification store backed by a `HashMap` (pending tokens) and a
/// `HashSet` (verified emails).  Suitable for tests and single-node development
/// setups — not for production use across multiple processes.
#[derive(Default, Clone)]
pub struct HashMapEmailVerificationTokenStore {
    pending: Arc<RwLock<HashMap<EmailVerificationToken, Email>>>,
    verified: Arc<RwLock<HashSet<Email>>>,
}

impl HashMapEmailVerificationTokenStore {
    pub fn new() -> Self {
        Self {
            pending: Arc::new(RwLock::new(HashMap::new())),
            verified: Arc::new(RwLock::new(HashSet::new())),
        }
    }
}

#[async_trait::async_trait]
impl EmailVerificationTokenStore for HashMapEmailVerificationTokenStore {
    async fn store_pending_verification(
        &self,
        token: EmailVerificationToken,
        email: Email,
    ) -> Result<(), EmailVerificationStoreError> {
        self.pending.write().await.insert(token, email);
        Ok(())
    }

    async fn consume_token(
        &self,
        token: &EmailVerificationToken,
    ) -> Result<Email, EmailVerificationStoreError> {
        self.pending
            .write()
            .await
            .remove(token)
            .ok_or(EmailVerificationStoreError::TokenNotFound)
    }

    async fn mark_verified(&self, email: &Email) -> Result<(), EmailVerificationStoreError> {
        self.verified.write().await.insert(email.clone());
        Ok(())
    }

    async fn is_verified(&self, email: &Email) -> Result<bool, EmailVerificationStoreError> {
        Ok(self.verified.read().await.contains(email))
    }
}
