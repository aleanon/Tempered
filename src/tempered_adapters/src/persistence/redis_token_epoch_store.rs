use std::sync::Arc;

use redis::Commands;
use secrecy::ExposeSecret;
use tokio::sync::RwLock;

use tempered_core::{Email, TokenEpochStore, TokenEpochStoreError};

use super::redis_support;

const TOKEN_EPOCH_PREFIX: &str = "token_epoch:";

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
        redis_support::try_lock_user(&mut *self.client.write().await, email, holder, ttl_seconds)
            .map_err(|e| TokenEpochStoreError::UnexpectedError(e.to_string()))
    }

    async fn unlock_user(&self, email: &Email, holder: &str) -> Result<(), TokenEpochStoreError> {
        redis_support::unlock_user(&mut *self.client.write().await, email, holder)
            .map_err(|e| TokenEpochStoreError::UnexpectedError(e.to_string()))
    }

    async fn is_user_locked(&self, email: &Email) -> Result<bool, TokenEpochStoreError> {
        redis_support::is_user_locked(&mut *self.client.write().await, email)
            .map_err(|e| TokenEpochStoreError::UnexpectedError(e.to_string()))
    }
}

fn get_key(email: &Email) -> String {
    format!("{}{}", TOKEN_EPOCH_PREFIX, email.as_ref().expose_secret())
}
