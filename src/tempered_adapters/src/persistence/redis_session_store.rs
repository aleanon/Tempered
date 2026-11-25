use std::sync::Arc;

use redis::{AsyncCommands, aio::ConnectionManager};
use secrecy::{ExposeSecret, Secret};

use tempered_core::{
    Email, SessionId, SessionRecord, SessionSeen, SessionStore, SessionStoreError,
};

use super::redis_support::{self, user_key};

const SESSION_PREFIX: &str = "session:";
const USER_SESSIONS_PREFIX: &str = "user_sessions:";
const REVOCATIONS_PREFIX: &str = "session_revocations:";

/// Read the session (`KEYS[1]`, JSON), record the visit (`last_seen` =
/// `ARGV[3]`; `user_agent` = `ARGV[4]` if it has none and that is not
/// empty), store it again with a new TTL (`ARGV[1]`), and `EXPIRE` the
/// owner's set (`ARGV[2]` + the address). Returns the value as it was, or
/// nil. One script, so the read, the update and both expiries are one round
/// trip and cannot interleave with another request's.
static TOUCH_SCRIPT: std::sync::LazyLock<redis::Script> = std::sync::LazyLock::new(|| {
    redis::Script::new(
        r"
        local value = redis.call('GET', KEYS[1])
        if not value then return false end
        local record = cjson.decode(value)
        record.last_seen = tonumber(ARGV[3])
        if (record.user_agent == nil or record.user_agent == cjson.null) and ARGV[4] ~= '' then
            record.user_agent = ARGV[4]
        end
        redis.call('SET', KEYS[1], cjson.encode(record), 'EX', ARGV[1])
        redis.call('EXPIRE', ARGV[2] .. record.email, ARGV[1])
        return value
        ",
    )
});

/// Redis-backed [`SessionStore`].
///
/// Keys (each after the store's namespace, if it has one):
/// - `session:{id}` → the [`SessionRecord`] as JSON, expiring after
///   `ttl_seconds` and refreshed by
///   [`touch_session`](SessionStore::touch_session) (sliding expiry);
/// - `user_sessions:{email}` → the set of the user's session ids, for
///   "log out everywhere";
/// - `session_revocations:{email}` → how often that ran. Never expires: if it
///   did, a login in flight across the expiry could miss a revocation.
///
/// Use the same TTL as the scheme's `SessionConfig::ttl_in_seconds`, so the
/// cookie and the session expire together.
///
/// **Two stores on one Redis** (login and elevated sessions) need their own
/// [`with_namespace`](Self::with_namespace): otherwise they share every key,
/// so "log out everywhere" in one empties the other and they share one
/// revocation counter. (Validation stays safe either way: a session records
/// which kind it is.)
#[derive(Clone)]
pub struct RedisSessionStore {
    client: ConnectionManager,
    ttl_seconds: u64,
    keys: Arc<Keys>,
}

/// The key prefixes, with the namespace applied.
struct Keys {
    session: String,
    user_sessions: String,
    revocations: String,
}

impl Keys {
    fn new(namespace: &str) -> Self {
        let ns = if namespace.is_empty() {
            String::new()
        } else {
            format!("{namespace}:")
        };
        Self {
            session: format!("{ns}{SESSION_PREFIX}"),
            user_sessions: format!("{ns}{USER_SESSIONS_PREFIX}"),
            revocations: format!("{ns}{REVOCATIONS_PREFIX}"),
        }
    }
}

impl RedisSessionStore {
    /// A store whose keys start `session:`, `user_sessions:` and
    /// `session_revocations:`.
    pub fn new(client: ConnectionManager, ttl_seconds: u64) -> Self {
        Self::with_namespace(client, ttl_seconds, "")
    }

    /// A store whose keys all start `{namespace}:` (for example
    /// `"elevated"`), apart from every other namespace on the server.
    pub fn with_namespace(client: ConnectionManager, ttl_seconds: u64, namespace: &str) -> Self {
        Self {
            client,
            ttl_seconds,
            keys: Arc::new(Keys::new(namespace)),
        }
    }

    fn session_key(&self, id: &SessionId) -> String {
        format!("{}{id}", self.keys.session)
    }
}

fn unexpected(e: impl std::error::Error + Send + Sync + 'static) -> SessionStoreError {
    // Keep the store's own error as the source (a caller can downcast it).
    SessionStoreError::UnexpectedError(tempered_core::Failure::new(e))
}

/// The stored form of a [`SessionRecord`].
#[derive(serde::Serialize, serde::Deserialize)]
struct Stored {
    email: String,
    user_id: tempered_core::UserId,
    created_at: u64,
    scope: String,
    #[serde(default)]
    last_seen: Option<u64>,
    #[serde(default)]
    user_agent: Option<String>,
}

fn encode(record: &SessionRecord) -> String {
    serde_json::to_string(&Stored {
        email: record.email.as_ref().expose_secret().clone(),
        user_id: record.user_id,
        created_at: record.created_at,
        scope: record.scope.clone(),
        last_seen: record.last_seen,
        user_agent: record.user_agent.clone(),
    })
    .expect("a session record serialises")
}

/// Read a stored record. A value in another shape is corrupt data, reported
/// as an error rather than as a missing session.
fn decode(value: Option<String>) -> Result<SessionRecord, SessionStoreError> {
    let value = value.ok_or(SessionStoreError::SessionNotFound)?;
    let stored: Stored = serde_json::from_str(&value).map_err(|e| {
        SessionStoreError::UnexpectedError(tempered_core::Failure::message(format!(
            "corrupt session: {e}"
        )))
    })?;
    let email = Email::try_from(Secret::new(stored.email))
        .map_err(|e| SessionStoreError::UnexpectedError(e.to_string().into()))?;
    Ok(SessionRecord {
        email,
        user_id: stored.user_id,
        created_at: stored.created_at,
        scope: stored.scope,
        last_seen: stored.last_seen,
        user_agent: stored.user_agent,
    })
}

#[async_trait::async_trait]
impl SessionStore for RedisSessionStore {
    async fn create_session(
        &self,
        id: SessionId,
        record: SessionRecord,
    ) -> Result<(), SessionStoreError> {
        let user_sessions = user_key(&self.keys.user_sessions, &record.email);
        // One transaction: a "delete all" listing the user's sessions sees
        // this one together with its key, or neither.
        redis::pipe()
            .atomic()
            .set_ex(self.session_key(&id), encode(&record), self.ttl_seconds)
            .ignore()
            .sadd(&user_sessions, id.to_string())
            .ignore()
            .expire(&user_sessions, self.ttl_seconds as i64)
            .ignore()
            .query_async::<()>(&mut self.client.clone())
            .await
            .map_err(unexpected)
    }

    async fn get_session(&self, id: &SessionId) -> Result<SessionRecord, SessionStoreError> {
        let value: Option<String> = self
            .client
            .clone()
            .get(self.session_key(id))
            .await
            .map_err(unexpected)?;
        decode(value)
    }

    async fn touch_session(
        &self,
        id: &SessionId,
        seen: SessionSeen<'_>,
    ) -> Result<SessionRecord, SessionStoreError> {
        let value: Option<String> = TOUCH_SCRIPT
            .key(self.session_key(id))
            .arg(self.ttl_seconds)
            .arg(&self.keys.user_sessions)
            .arg(seen.at)
            .arg(seen.user_agent.unwrap_or(""))
            .invoke_async(&mut self.client.clone())
            .await
            .map_err(unexpected)?;
        decode(value)
    }

    async fn list_for_user(
        &self,
        email: &Email,
    ) -> Result<Vec<(SessionId, SessionRecord)>, SessionStoreError> {
        let mut client = self.client.clone();
        let set = user_key(&self.keys.user_sessions, email);
        let ids: Vec<String> = client.smembers(&set).await.map_err(unexpected)?;
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let keys: Vec<String> = ids
            .iter()
            .map(|id| format!("{}{id}", self.keys.session))
            .collect();
        let values: Vec<Option<String>> = client.mget(&keys).await.map_err(unexpected)?;
        let mut live = Vec::new();
        for (id, value) in ids.into_iter().zip(values) {
            // Expired sessions linger in the set until it expires; skip them.
            let (Some(value), Some(id)) = (value, SessionId::parse(&id)) else {
                continue;
            };
            live.push((id, decode(Some(value))?));
        }
        Ok(live)
    }

    async fn delete_session(&self, id: &SessionId) -> Result<(), SessionStoreError> {
        let mut client = self.client.clone();
        let value: Option<String> = client
            .get_del(self.session_key(id))
            .await
            .map_err(unexpected)?;
        let email = decode(value)?.email;
        let _: i64 = client
            .srem(user_key(&self.keys.user_sessions, &email), id.to_string())
            .await
            .map_err(unexpected)?;
        Ok(())
    }

    async fn delete_all_for_user(&self, email: &Email) -> Result<(), SessionStoreError> {
        let mut client = self.client.clone();
        // Count first (the port's contract): a session created after this
        // sees the new count and discards itself, so the listing below may
        // miss it safely.
        let _: u64 = client
            .incr(user_key(&self.keys.revocations, email), 1)
            .await
            .map_err(unexpected)?;

        let user_sessions = user_key(&self.keys.user_sessions, email);
        let ids: Vec<String> = client.smembers(&user_sessions).await.map_err(unexpected)?;
        if ids.is_empty() {
            return Ok(());
        }
        let mut pipe = redis::pipe();
        pipe.atomic();
        for id in &ids {
            pipe.del(format!("{}{id}", self.keys.session)).ignore();
        }
        pipe.srem(&user_sessions, ids).ignore();
        pipe.query_async::<()>(&mut client)
            .await
            .map_err(unexpected)
    }

    async fn revocation_count(&self, email: &Email) -> Result<u64, SessionStoreError> {
        let count: Option<u64> = self
            .client
            .clone()
            .get(user_key(&self.keys.revocations, email))
            .await
            .map_err(unexpected)?;
        Ok(count.unwrap_or(0))
    }

    async fn try_lock_user(
        &self,
        email: &Email,
        holder: &str,
        ttl_seconds: u64,
    ) -> Result<bool, SessionStoreError> {
        redis_support::try_lock_user(&mut self.client.clone(), email, holder, ttl_seconds)
            .await
            .map_err(unexpected)
    }

    async fn unlock_user(&self, email: &Email, holder: &str) -> Result<(), SessionStoreError> {
        redis_support::unlock_user(&mut self.client.clone(), email, holder)
            .await
            .map_err(unexpected)
    }

    async fn is_user_locked(&self, email: &Email) -> Result<bool, SessionStoreError> {
        redis_support::is_user_locked(&mut self.client.clone(), email)
            .await
            .map_err(unexpected)
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
            .create_session(
                id.clone(),
                SessionRecord {
                    email: contract::email("a@example.com"),
                    user_id: tempered_core::UserId::new(),
                    created_at: 1,
                    scope: "s".to_string(),
                    last_seen: None,
                    user_agent: None,
                },
            )
            .await
            .unwrap();

        let mut connection = connection;
        let key = store.session_key(&id);
        let ttl: i64 = connection.ttl(&key).await.unwrap();
        assert!((1..=60).contains(&ttl));
        let set = user_key(&store.keys.user_sessions, &contract::email("a@example.com"));
        let _: bool = connection.expire(&key, 5).await.unwrap();
        let _: bool = connection.expire(&set, 5).await.unwrap();
        let seen = tempered_core::SessionSeen {
            at: 2,
            user_agent: None,
        };
        let record = store.touch_session(&id, seen).await.unwrap();
        assert_eq!(record.created_at, 1);
        // Both the session and the user's set were slid.
        let ttl: i64 = connection.ttl(&key).await.unwrap();
        assert!(ttl > 5);
        let ttl: i64 = connection.ttl(&set).await.unwrap();
        assert!(ttl > 5);
    }

    /// Two stores on one server, in their own namespaces, are separate: a
    /// session of one is not found in the other, and "log out everywhere"
    /// in one leaves the other alone.
    #[tokio::test]
    async fn namespaced_stores_do_not_share_sessions() {
        let (_redis, connection) = test_support::redis::connection().await;
        let login = RedisSessionStore::new(connection.clone(), 60);
        let elevated = RedisSessionStore::with_namespace(connection, 60, "elevated");
        let alice = contract::email("a@example.com");
        let record = |scope: &str| SessionRecord {
            email: alice.clone(),
            user_id: tempered_core::UserId::new(),
            created_at: 1,
            scope: scope.to_string(),
            last_seen: None,
            user_agent: None,
        };
        let (l, e) = (SessionId::new(), SessionId::new());
        login.create_session(l.clone(), record("s")).await.unwrap();
        elevated
            .create_session(e.clone(), record("e"))
            .await
            .unwrap();

        assert!(matches!(
            elevated.get_session(&l).await,
            Err(SessionStoreError::SessionNotFound)
        ));
        assert!(matches!(
            login.get_session(&e).await,
            Err(SessionStoreError::SessionNotFound)
        ));

        elevated.delete_all_for_user(&alice).await.unwrap();
        assert!(login.get_session(&l).await.is_ok());
        assert_eq!(login.revocation_count(&alice).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_session_stored_without_its_creation_time_is_an_error() {
        let (_redis, mut connection) = test_support::redis::connection().await;
        let store = RedisSessionStore::new(connection.clone(), 60);
        let id = SessionId::new();
        let _: () = connection
            .set(store.session_key(&id), "a@example.com")
            .await
            .unwrap();
        assert!(matches!(
            store.get_session(&id).await,
            Err(SessionStoreError::UnexpectedError(_))
        ));
    }
}
