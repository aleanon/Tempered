use redis::{AsyncCommands, aio::ConnectionManager};
use secrecy::ExposeSecret;

use tempered_core::{Email, TokenEpochStore, TokenEpochStoreError};

use super::redis_support;

const TOKEN_EPOCH_PREFIX: &str = "token_epoch:";

/// Redis-backed [`TokenEpochStore`], keyed `token_epoch:{email}`.
#[derive(Clone)]
pub struct RedisTokenEpochStore {
    client: ConnectionManager,
    ttl_seconds: u64,
}

impl RedisTokenEpochStore {
    /// `ttl_seconds` bounds how long a cutoff is kept and MUST be at least the
    /// longest TTL of any token this store guards (the trait contract): if the
    /// cutoff expires while a revoked token is still within its `exp`, that
    /// token becomes valid again.
    pub fn new(client: ConnectionManager, ttl_seconds: u64) -> Self {
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
            .clone()
            .get(key)
            .await
            .map_err(|e| TokenEpochStoreError::UnexpectedError(e.to_string()))
    }

    async fn revoke_before(&self, email: &Email, cutoff: i64) -> Result<(), TokenEpochStoreError> {
        // Keep the highest cutoff (contract: never lower it), compared and
        // written in one script. A GET followed by a SET let two instances
        // interleave: A reads 100, B writes 105, A writes 101, and tokens
        // B meant to revoke validated again.
        let script = redis::Script::new(
            "local current = tonumber(redis.call('get', KEYS[1])) \
             local cutoff = tonumber(ARGV[1]) \
             if current and current > cutoff then cutoff = current end \
             redis.call('set', KEYS[1], cutoff, 'EX', ARGV[2]) \
             return cutoff",
        );
        let _: i64 = script
            .key(get_key(email))
            .arg(cutoff)
            .arg(self.ttl_seconds)
            .invoke_async(&mut self.client.clone())
            .await
            .map_err(|e| TokenEpochStoreError::UnexpectedError(e.to_string()))?;
        Ok(())
    }

    async fn try_lock_user(
        &self,
        email: &Email,
        holder: &str,
        ttl_seconds: u64,
    ) -> Result<bool, TokenEpochStoreError> {
        redis_support::try_lock_user(&mut self.client.clone(), email, holder, ttl_seconds)
            .await
            .map_err(|e| TokenEpochStoreError::UnexpectedError(e.to_string()))
    }

    async fn unlock_user(&self, email: &Email, holder: &str) -> Result<(), TokenEpochStoreError> {
        redis_support::unlock_user(&mut self.client.clone(), email, holder)
            .await
            .map_err(|e| TokenEpochStoreError::UnexpectedError(e.to_string()))
    }

    async fn is_user_locked(&self, email: &Email) -> Result<bool, TokenEpochStoreError> {
        redis_support::is_user_locked(&mut self.client.clone(), email)
            .await
            .map_err(|e| TokenEpochStoreError::UnexpectedError(e.to_string()))
    }
}

fn get_key(email: &Email) -> String {
    format!("{}{}", TOKEN_EPOCH_PREFIX, email.as_ref().expose_secret())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{contract, test_support};

    #[tokio::test]
    async fn meets_the_token_epoch_store_contract() {
        let (_redis, connection) = test_support::redis::connection().await;
        contract::token_epoch_store(RedisTokenEpochStore::new(connection, 3600)).await;
    }
}
