use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use tempered_core::{Email, SessionId, SessionStore, SessionStoreError};

/// In-memory session store for tests and local development.
///
/// Maps a `SessionId` to the owning user's email. Sessions do not expire
/// in-memory (`touch_session` is a no-op); the production `RedisSessionStore`
/// is responsible for TTL/sliding-window expiry.
#[derive(Default, Clone)]
pub struct HashMapSessionStore {
    sessions: Arc<RwLock<HashMap<SessionId, Email>>>,
}

impl HashMapSessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl SessionStore for HashMapSessionStore {
    async fn create_session(&self, id: SessionId, email: Email) -> Result<(), SessionStoreError> {
        self.sessions.write().await.insert(id, email);
        Ok(())
    }

    async fn get_session(&self, id: &SessionId) -> Result<Email, SessionStoreError> {
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
        self.sessions.write().await.retain(|_, v| v != email);
        Ok(())
    }
}
