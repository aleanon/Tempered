use std::sync::Arc;

use redis::Commands;
use secrecy::ExposeSecret;
use tokio::sync::RwLock;

use tempered_core::{Email, TokenEpochStore, TokenEpochStoreError};

const TOKEN_EPOCH_PREFIX: &str = "token_epoch:";
const USER_LOCK_PREFIX: &str = "user_lock:";

/// Redis-backed [`TokenEpochStore`], keyed `token_epoch:{email}`.
#[derive(Clone)]
pub struct RedisTokenEpochStore {
    client: Arc<RwLock<redis::Connection>>,
    ttl_seconds: u64,
}

impl RedisTokenEpochStore {
    /// `ttl_seconds` bounds how long a cutoff is kept and MUST be at least the
    /// longest TTL of any token this store guards (the trait contract): if the
    /// cutoff expires while a revoked token is still within its `exp`, that
    /// token becomes valid again.
    pub fn new(client: Arc<RwLock<redis::Connection>>, ttl_seconds: u64) -> Self {
        Self {
            client,
            ttl_seconds,
        }
    }
}

#[async_trait::async_trait]
impl TokenEpochStore for RedisTokenEpochStore {
    async fn min_valid_iat(&self, email: &Email) -> Result<Option<i64>, TokenEpochStoreError> {
        let key = get_key(email);
        self.client
            .write()
            .await
            .get(key)
            .map_err(|e| TokenEpochStoreError::UnexpectedError(e.to_string()))
    }

    async fn revoke_before(&self, email: &Email, cutoff: i64) -> Result<(), TokenEpochStoreError> {
        let key = get_key(email);
        let mut client = self.client.write().await;

        // Keep the highest cutoff (contract: never lower it). Cutoffs are
        // wall-clock "now" values, so a lost race between two near-simultaneous
        // revocations writes an equivalent value.
        let existing: Option<i64> = client
            .get(&key)
            .map_err(|e| TokenEpochStoreError::UnexpectedError(e.to_string()))?;
        let cutoff = existing.map_or(cutoff, |e| e.max(cutoff));

        let _: () = client
            .set_ex(&key, cutoff, self.ttl_seconds)
            .map_err(|e| TokenEpochStoreError::UnexpectedError(e.to_string()))?;
        Ok(())
    }

    async fn try_lock_user(
        &self,
        email: &Email,
        holder: &str,
        ttl_seconds: u64,
    ) -> Result<bool, TokenEpochStoreError> {
        // SET NX EX: atomic take with an expiry. Replies OK, or nil if held.
        let reply: Option<String> = redis::cmd("SET")
            .arg(lock_key(email))
            .arg(holder)
            .arg("NX")
            .arg("EX")
            .arg(ttl_seconds)
            .query(&mut *self.client.write().await)
            .map_err(|e| TokenEpochStoreError::UnexpectedError(e.to_string()))?;
        Ok(reply.is_some())
    }

    async fn unlock_user(&self, email: &Email, holder: &str) -> Result<(), TokenEpochStoreError> {
        // Compare-and-delete in one step, so an expired holder cannot release
        // a lock someone else has taken since.
        let script = redis::Script::new(
            "if redis.call('get', KEYS[1]) == ARGV[1] then \
                 return redis.call('del', KEYS[1]) \
             else return 0 end",
        );
        let _: i64 = script
            .key(lock_key(email))
            .arg(holder)
            .invoke(&mut *self.client.write().await)
            .map_err(|e| TokenEpochStoreError::UnexpectedError(e.to_string()))?;
        Ok(())
    }

    async fn is_user_locked(&self, email: &Email) -> Result<bool, TokenEpochStoreError> {
        self.client
            .write()
            .await
            .exists(lock_key(email))
            .map_err(|e| TokenEpochStoreError::UnexpectedError(e.to_string()))
    }
}

fn lock_key(email: &Email) -> String {
    format!("{}{}", USER_LOCK_PREFIX, email.as_ref().expose_secret())
}

fn get_key(email: &Email) -> String {
    format!("{}{}", TOKEN_EPOCH_PREFIX, email.as_ref().expose_secret())
}
