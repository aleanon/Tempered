use std::sync::Arc;

use redis::Commands;
use secrecy::{ExposeSecret, Secret};
use tokio::sync::RwLock;

use tempered_core::{Email, SessionId, SessionStore, SessionStoreError};

use super::redis_support::{self, user_key};

const SESSION_PREFIX: &str = "session:";
const USER_SESSIONS_PREFIX: &str = "user_sessions:";
const REVOCATIONS_PREFIX: &str = "session_revocations:";

/// Redis-backed [`SessionStore`].
///
/// Keys:
/// - `session:{id}` → the owner's email, expiring after `ttl_seconds` and
///   refreshed by [`touch_session`](SessionStore::touch_session) (sliding
///   expiry);
/// - `user_sessions:{email}` → the set of the user's session ids, for
///   "log out everywhere";
/// - `session_revocations:{email}` → how often that ran. Never expires: if it
///   did, a login in flight across the expiry could miss a revocation.
///
/// Use the same TTL as the scheme's `SessionConfig::ttl_in_seconds`, so the
/// cookie and the session expire together.
#[derive(Clone)]
pub struct RedisSessionStore {
    client: Arc<RwLock<redis::Connection>>,
    ttl_seconds: u64,
}

impl RedisSessionStore {
    pub fn new(client: Arc<RwLock<redis::Connection>>, ttl_seconds: u64) -> Self {
        Self {
            client,
            ttl_seconds,
        }
    }
}

fn unexpected(e: redis::RedisError) -> SessionStoreError {
    SessionStoreError::UnexpectedError(e.to_string())
}

fn session_key(id: &SessionId) -> String {
    format!("{SESSION_PREFIX}{id}")
}

fn parse_email(value: String) -> Result<Email, SessionStoreError> {
    Email::try_from(Secret::new(value))
        .map_err(|e| SessionStoreError::UnexpectedError(e.to_string()))
}

#[async_trait::async_trait]
impl SessionStore for RedisSessionStore {
    async fn create_session(&self, id: SessionId, email: Email) -> Result<(), SessionStoreError> {
        let user_sessions = user_key(USER_SESSIONS_PREFIX, &email);
        // One transaction: a "delete all" listing the user's sessions sees
        // this one together with its key, or neither.
        redis::pipe()
            .atomic()
            .set_ex(
                session_key(&id),
                email.as_ref().expose_secret(),
                self.ttl_seconds,
            )
            .ignore()
            .sadd(&user_sessions, id.to_string())
            .ignore()
            .expire(&user_sessions, self.ttl_seconds as i64)
            .ignore()
            .query::<()>(&mut *self.client.write().await)
            .map_err(unexpected)
    }

    async fn get_session(&self, id: &SessionId) -> Result<Email, SessionStoreError> {
        let email: Option<String> = self
            .client
            .write()
            .await
            .get(session_key(id))
            .map_err(unexpected)?;
        parse_email(email.ok_or(SessionStoreError::SessionNotFound)?)
    }

    async fn touch_session(&self, id: &SessionId) -> Result<(), SessionStoreError> {
        let mut client = self.client.write().await;
        let email: Option<String> = client
            .get_ex(session_key(id), redis::Expiry::EX(self.ttl_seconds))
            .map_err(unexpected)?;
        let email = parse_email(email.ok_or(SessionStoreError::SessionNotFound)?)?;
        // The user's set must live as long as their longest session.
        let _: bool = client
            .expire(
                user_key(USER_SESSIONS_PREFIX, &email),
                self.ttl_seconds as i64,
            )
            .map_err(unexpected)?;
        Ok(())
    }

    async fn delete_session(&self, id: &SessionId) -> Result<(), SessionStoreError> {
        let mut client = self.client.write().await;
        let email: Option<String> = client.get_del(session_key(id)).map_err(unexpected)?;
        let email = parse_email(email.ok_or(SessionStoreError::SessionNotFound)?)?;
        let _: i64 = client
            .srem(user_key(USER_SESSIONS_PREFIX, &email), id.to_string())
            .map_err(unexpected)?;
        Ok(())
    }

    async fn delete_all_for_user(&self, email: &Email) -> Result<(), SessionStoreError> {
        let mut client = self.client.write().await;
        // Count first (the port's contract): a session created after this
        // sees the new count and discards itself, so the listing below may
        // miss it safely.
        let _: u64 = client
            .incr(user_key(REVOCATIONS_PREFIX, email), 1)
            .map_err(unexpected)?;

        let user_sessions = user_key(USER_SESSIONS_PREFIX, email);
        let ids: Vec<String> = client.smembers(&user_sessions).map_err(unexpected)?;
        if ids.is_empty() {
            return Ok(());
        }
        let mut pipe = redis::pipe();
        pipe.atomic();
        for id in &ids {
            pipe.del(format!("{SESSION_PREFIX}{id}")).ignore();
        }
        pipe.srem(&user_sessions, ids).ignore();
        pipe.query::<()>(&mut *client).map_err(unexpected)
    }

    async fn revocation_count(&self, email: &Email) -> Result<u64, SessionStoreError> {
        let count: Option<u64> = self
            .client
            .write()
            .await
            .get(user_key(REVOCATIONS_PREFIX, email))
            .map_err(unexpected)?;
        Ok(count.unwrap_or(0))
    }

    async fn try_lock_user(
        &self,
        email: &Email,
        holder: &str,
        ttl_seconds: u64,
    ) -> Result<bool, SessionStoreError> {
        redis_support::try_lock_user(&mut *self.client.write().await, email, holder, ttl_seconds)
            .map_err(unexpected)
    }

    async fn unlock_user(&self, email: &Email, holder: &str) -> Result<(), SessionStoreError> {
        redis_support::unlock_user(&mut *self.client.write().await, email, holder)
            .map_err(unexpected)
    }

    async fn is_user_locked(&self, email: &Email) -> Result<bool, SessionStoreError> {
        redis_support::is_user_locked(&mut *self.client.write().await, email).map_err(unexpected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{contract, test_support};

    #[tokio::test]
    async fn meets_the_session_store_contract() {
        let (_redis, connection) = test_support::redis::connection().await;
        contract::session_store(RedisSessionStore::new(connection, 60)).await;
    }

    #[tokio::test]
    async fn a_session_expires_with_its_ttl_and_touch_extends_it() {
        let (_redis, connection) = test_support::redis::connection().await;
        let store = RedisSessionStore::new(connection.clone(), 60);
        let id = SessionId::new();
        store
            .create_session(id.clone(), contract::email("a@example.com"))
            .await
            .unwrap();

        let ttl = |c: &mut redis::Connection| -> i64 { c.ttl(session_key(&id)).unwrap() };
        assert!((1..=60).contains(&ttl(&mut *connection.write().await)));
        let _: bool = connection
            .write()
            .await
            .expire(session_key(&id), 5)
            .unwrap();
        store.touch_session(&id).await.unwrap();
        assert!(ttl(&mut *connection.write().await) > 5);
    }
}
