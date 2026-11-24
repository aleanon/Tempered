use std::sync::Arc;

use redis::{AsyncCommands, aio::ConnectionManager};
use secrecy::{ExposeSecret, Secret};

use tempered_core::{Email, SessionId, SessionRecord, SessionStore, SessionStoreError};

use super::redis_support::{self, user_key};

const SESSION_PREFIX: &str = "session:";
const USER_SESSIONS_PREFIX: &str = "user_sessions:";
const REVOCATIONS_PREFIX: &str = "session_revocations:";

/// `GETEX` the session (`KEYS[1]`) with a new TTL (`ARGV[1]`), then `EXPIRE`
/// the owner's set (`ARGV[2]` + the address, after the second `:` of
/// `{created_at}:{scope}:{email}`). Returns the value, or nil.
static TOUCH_SCRIPT: std::sync::LazyLock<redis::Script> = std::sync::LazyLock::new(|| {
    redis::Script::new(
        r"
        local value = redis.call('GETEX', KEYS[1], 'EX', ARGV[1])
        if not value then return false end
        local first = string.find(value, ':', 1, true)
        local second = first and string.find(value, ':', first + 1, true)
        if second then
            redis.call('EXPIRE', ARGV[2] .. string.sub(value, second + 1), ARGV[1])
        end
        return value
        ",
    )
});

/// Redis-backed [`SessionStore`].
///
/// Keys (each after the store's namespace, if it has one):
/// - `session:{id}` → `{created_at}:{scope}:{email}` (creation time in Unix
///   seconds, the session's [`scope`](SessionRecord::scope), then the
///   owner's address), expiring after `ttl_seconds` and refreshed by
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

fn unexpected(e: redis::RedisError) -> SessionStoreError {
    SessionStoreError::UnexpectedError(e.to_string())
}

fn encode(record: &SessionRecord) -> String {
    format!(
        "{}:{}:{}",
        record.created_at,
        record.scope,
        record.email.as_ref().expose_secret()
    )
}

/// Read a stored `{created_at}:{scope}:{email}`. A value in another shape is
/// corrupt data, reported as an error rather than as a missing session.
fn decode(value: Option<String>) -> Result<SessionRecord, SessionStoreError> {
    let corrupt =
        |what: &str| SessionStoreError::UnexpectedError(format!("corrupt session: {what}"));
    let value = value.ok_or(SessionStoreError::SessionNotFound)?;
    let (created_at, rest) = value
        .split_once(':')
        .ok_or_else(|| corrupt("no creation time"))?;
    let (scope, email) = rest.split_once(':').ok_or_else(|| corrupt("no scope"))?;
    let created_at = created_at
        .parse()
        .map_err(|_| corrupt("creation time is not a number"))?;
    let email = Email::try_from(Secret::new(email.to_string()))
        .map_err(|e| SessionStoreError::UnexpectedError(e.to_string()))?;
    Ok(SessionRecord {
        email,
        created_at,
        scope: scope.to_string(),
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

    async fn touch_session(&self, id: &SessionId) -> Result<SessionRecord, SessionStoreError> {
        // One round trip: the script reads and slides the session, then
        // extends the user's set, which must live as long as their longest
        // session.
        let value: Option<String> = TOUCH_SCRIPT
            .key(self.session_key(id))
            .arg(self.ttl_seconds)
            .arg(&self.keys.user_sessions)
            .invoke_async(&mut self.client.clone())
            .await
            .map_err(unexpected)?;
        decode(value)
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
                    created_at: 1,
                    scope: "s".to_string(),
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
        let record = store.touch_session(&id).await.unwrap();
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
            created_at: 1,
            scope: scope.to_string(),
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
