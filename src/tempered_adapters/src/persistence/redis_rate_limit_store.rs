use redis::aio::ConnectionManager;

use tempered_core::{RateLimitStore, RateLimitStoreError, WindowCount};

const PREFIX: &str = "rate_limit:";

/// `INCR` the key (`KEYS[1]`); on the window's first hit, `EXPIRE` it after
/// `ARGV[1]` seconds. Returns `{count, ttl}`. One script, so the count and
/// the expiry cannot be split by a crash between two commands (which would
/// leave a counter that never resets).
static HIT_SCRIPT: std::sync::LazyLock<redis::Script> = std::sync::LazyLock::new(|| {
    redis::Script::new(
        r"
        local count = redis.call('INCR', KEYS[1])
        if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
        local ttl = redis.call('TTL', KEYS[1])
        if ttl < 0 then
            redis.call('EXPIRE', KEYS[1], ARGV[1])
            ttl = tonumber(ARGV[1])
        end
        return {count, ttl}
        ",
    )
});

/// Redis-backed [`RateLimitStore`]: one counter per key under
/// `rate_limit:`, expiring with its window, shared by every instance.
#[derive(Clone)]
pub struct RedisRateLimitStore {
    client: ConnectionManager,
}

impl RedisRateLimitStore {
    pub fn new(client: ConnectionManager) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl RateLimitStore for RedisRateLimitStore {
    async fn hit(
        &self,
        key: &str,
        window_seconds: u64,
    ) -> Result<WindowCount, RateLimitStoreError> {
        let (count, ttl): (u64, i64) = HIT_SCRIPT
            .key(format!("{PREFIX}{key}"))
            .arg(window_seconds)
            .invoke_async(&mut self.client.clone())
            .await
            .map_err(|e| RateLimitStoreError::UnexpectedError(e.to_string()))?;
        Ok(WindowCount {
            count,
            resets_in_seconds: ttl.max(1) as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{contract, test_support};

    #[tokio::test]
    async fn meets_the_rate_limit_store_contract() {
        let (_redis, connection) = test_support::redis::connection().await;
        contract::rate_limit_store(RedisRateLimitStore::new(connection)).await;
    }
}
