use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tempered_core::{Email, EmailChangeStore, EmailChangeStoreError};

/// In-memory [`EmailChangeStore`].
///
/// # Warning: development and tests only
///
/// Pending changes are lost on restart (the user asks again). Use
/// [`RedisEmailChangeStore`](super::redis_email_change_store::RedisEmailChangeStore)
/// in production.
#[derive(Default, Clone)]
pub struct HashMapEmailChangeStore {
    pending: Arc<Mutex<HashMap<[u8; 32], Pending>>>,
}

struct Pending {
    old: Email,
    new: Email,
    until: Instant,
}

impl HashMapEmailChangeStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl EmailChangeStore for HashMapEmailChangeStore {
    async fn create(
        &self,
        token: [u8; 32],
        old: Email,
        new: Email,
        ttl_seconds: u64,
    ) -> Result<(), EmailChangeStoreError> {
        let mut pending = self.pending.lock().expect("email change map poisoned");
        let now = Instant::now();
        // One pending change per account: the newest wins.
        pending.retain(|_, p| p.old != old && p.until > now);
        let until = now + Duration::from_secs(ttl_seconds);
        pending.insert(token, Pending { old, new, until });
        Ok(())
    }

    async fn consume(&self, token: &[u8; 32]) -> Result<(Email, Email), EmailChangeStoreError> {
        let mut pending = self.pending.lock().expect("email change map poisoned");
        match pending.remove(token) {
            Some(p) if p.until > Instant::now() => Ok((p.old, p.new)),
            _ => Err(EmailChangeStoreError::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn meets_the_email_change_store_contract() {
        crate::persistence::contract::email_change_store(HashMapEmailChangeStore::new()).await;
    }
}
