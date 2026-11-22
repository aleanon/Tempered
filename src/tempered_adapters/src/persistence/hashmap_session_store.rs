use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use tempered_core::{Email, SessionId, SessionRecord, SessionStore, SessionStoreError};

/// In-memory session store for tests and local development.
///
/// Maps a `SessionId` to the owning user's email. Sessions do not expire
/// in-memory (`touch_session` is a no-op); the production `RedisSessionStore`
/// is responsible for TTL/sliding-window expiry.
#[derive(Default, Clone)]
pub struct HashMapSessionStore {
    sessions: Arc<RwLock<HashMap<SessionId, SessionRecord>>>,
    revocations: Arc<RwLock<HashMap<Email, u64>>>,
    locks: super::user_locks::UserLocks,
}

impl HashMapSessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            revocations: Arc::new(RwLock::new(HashMap::new())),
            locks: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl SessionStore for HashMapSessionStore {
    async fn create_session(
        &self,
        id: SessionId,
        record: SessionRecord,
    ) -> Result<(), SessionStoreError> {
        self.sessions.write().await.insert(id, record);
        Ok(())
    }

    async fn get_session(&self, id: &SessionId) -> Result<SessionRecord, SessionStoreError> {
        self.sessions
            .read()
            .await
            .get(id)
            .cloned()
            .ok_or(SessionStoreError::SessionNotFound)
    }

    async fn touch_session(&self, _id: &SessionId) -> Result<(), SessionStoreError> {
        // No expiry in-memory.
        Ok(())
    }

    async fn delete_session(&self, id: &SessionId) -> Result<(), SessionStoreError> {
        self.sessions
            .write()
            .await
            .remove(id)
            .ok_or(SessionStoreError::SessionNotFound)?;
        Ok(())
    }

    async fn delete_all_for_user(&self, email: &Email) -> Result<(), SessionStoreError> {
        // Count first, delete second (the port's contract).
        *self
            .revocations
            .write()
            .await
            .entry(email.clone())
            .or_default() += 1;
        self.sessions.write().await.retain(|_, v| &v.email != email);
        Ok(())
    }

    async fn revocation_count(&self, email: &Email) -> Result<u64, SessionStoreError> {
        Ok(self
            .revocations
            .read()
            .await
            .get(email)
            .copied()
            .unwrap_or(0))
    }

    async fn try_lock_user(
        &self,
        email: &Email,
        holder: &str,
        ttl_seconds: u64,
    ) -> Result<bool, SessionStoreError> {
        Ok(self.locks.try_lock(email, holder, ttl_seconds).await)
    }

    async fn unlock_user(&self, email: &Email, holder: &str) -> Result<(), SessionStoreError> {
        self.locks.unlock(email, holder).await;
        Ok(())
    }

    async fn is_user_locked(&self, email: &Email) -> Result<bool, SessionStoreError> {
        Ok(self.locks.is_locked(email).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn meets_the_session_store_contract() {
        crate::persistence::contract::session_store(HashMapSessionStore::new()).await;
    }
}
