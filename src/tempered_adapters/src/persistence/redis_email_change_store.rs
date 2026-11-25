use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::aio::ConnectionManager;
use secrecy::{ExposeSecret, Secret};

use tempered_core::{Email, EmailChangeStore, EmailChangeStoreError};

use super::redis_support::user_key;

const TOKEN_PREFIX: &str = "email_change:";
const USER_PREFIX: &str = "email_change_user:";

/// Redis-backed [`EmailChangeStore`]:
/// - `email_change:{hash}` → `{old}\n{new}`, expiring with the change;
/// - `email_change_user:{old}` → the account's current token, so a newer
///   request removes the older one.
#[derive(Clone)]
pub struct RedisEmailChangeStore {
    client: ConnectionManager,
}

impl RedisEmailChangeStore {
    pub fn new(client: ConnectionManager) -> Self {
        Self { client }
    }
}

/// `KEYS`: token, user index. `ARGV`: value, TTL, token key. Drops the
/// account's previous pending change and stores this one.
static CREATE_SCRIPT: std::sync::LazyLock<redis::Script> = std::sync::LazyLock::new(|| {
    redis::Script::new(
        r"
        local previous = redis.call('GET', KEYS[2])
        if previous then redis.call('DEL', previous) end
        redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
        redis.call('SET', KEYS[2], ARGV[3], 'EX', ARGV[2])
        return 1
        ",
    )
});

fn unexpected(e: impl std::error::Error + Send + Sync + 'static) -> EmailChangeStoreError {
    EmailChangeStoreError::UnexpectedError(tempered_core::Failure::new(e))
}

fn token_key(token: &[u8; 32]) -> String {
    format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(token))
}

#[async_trait::async_trait]
impl EmailChangeStore for RedisEmailChangeStore {
    async fn create(
        &self,
        token: [u8; 32],
        old: Email,
        new: Email,
        ttl_seconds: u64,
    ) -> Result<(), EmailChangeStoreError> {
        let key = token_key(&token);
        let value = format!(
            "{}\n{}",
            old.as_ref().expose_secret(),
            new.as_ref().expose_secret()
        );
        let _: i64 = CREATE_SCRIPT
            .key(&key)
            .key(user_key(USER_PREFIX, &old))
            .arg(value)
            .arg(ttl_seconds.max(1))
            .arg(&key)
            .invoke_async(&mut self.client.clone())
            .await
            .map_err(unexpected)?;
        Ok(())
    }

    async fn consume(&self, token: &[u8; 32]) -> Result<(Email, Email), EmailChangeStoreError> {
        use redis::AsyncCommands;
        let value: Option<String> = self
            .client
            .clone()
            .get_del(token_key(token))
            .await
            .map_err(unexpected)?;
        let value = value.ok_or(EmailChangeStoreError::NotFound)?;
        let (old, new) = value
            .split_once('\n')
            .ok_or_else(|| EmailChangeStoreError::UnexpectedError("corrupt email change".into()))?;
        let parse = |s: &str| Email::try_from(Secret::new(s.to_string())).map_err(unexpected);
        Ok((parse(old)?, parse(new)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{contract, test_support};

    #[tokio::test]
    async fn meets_the_email_change_store_contract() {
        let (_redis, connection) = test_support::redis::connection().await;
        contract::email_change_store(RedisEmailChangeStore::new(connection)).await;
    }
}
