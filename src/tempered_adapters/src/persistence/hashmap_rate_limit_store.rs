use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tempered_core::{RateLimitStore, RateLimitStoreError, WindowCount};

/// In-memory [`RateLimitStore`].
///
/// # Warning: development and tests only
///
/// Counts are per process: with several instances each counts on its own,
/// so the real limit is the configured one times the instance count. Use
/// [`RedisRateLimitStore`](super::redis_rate_limit_store::RedisRateLimitStore)
/// in production.
#[derive(Default, Clone)]
pub struct HashMapRateLimitStore {
    /// key → (hits, window end).
    windows: Arc<Mutex<HashMap<String, (u64, Instant)>>>,
}

impl HashMapRateLimitStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl RateLimitStore for HashMapRateLimitStore {
    async fn hit(
        &self,
        key: &str,
        window_seconds: u64,
    ) -> Result<WindowCount, RateLimitStoreError> {
        let now = Instant::now();
        let mut windows = self.windows.lock().expect("rate limit map poisoned");
        // Ended windows are dropped as they are seen, so the map stays the
        // size of the active keys.
        if windows.len() > 10_000 {
            windows.retain(|_, (_, end)| *end > now);
        }
        let entry = windows
            .entry(key.to_string())
            .or_insert((0, now + Duration::from_secs(window_seconds)));
        if entry.1 <= now {
            *entry = (0, now + Duration::from_secs(window_seconds));
        }
        entry.0 += 1;
        Ok(WindowCount {
            count: entry.0,
            resets_in_seconds: entry.1.saturating_duration_since(now).as_secs().max(1),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn meets_the_rate_limit_store_contract() {
        crate::persistence::contract::rate_limit_store(HashMapRateLimitStore::new()).await;
    }
}
