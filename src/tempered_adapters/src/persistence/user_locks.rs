//! The in-memory credential-lock table shared by the `HashMap*` stores that
//! offer one (see `TokenEpochStore::try_lock_user`).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tempered_core::Email;
use tokio::sync::Mutex;
use tokio::time::Instant;

#[derive(Default, Clone)]
pub(crate) struct UserLocks {
    held: Arc<Mutex<HashMap<Email, (String, Instant)>>>,
}

impl UserLocks {
    pub(crate) async fn try_lock(&self, email: &Email, holder: &str, ttl_seconds: u64) -> bool {
        let mut held = self.held.lock().await;
        let now = Instant::now();
        if let Some((_, expires)) = held.get(email)
            && *expires > now
        {
            return false;
        }
        held.insert(
            email.clone(),
            (holder.to_string(), now + Duration::from_secs(ttl_seconds)),
        );
        true
    }

    pub(crate) async fn unlock(&self, email: &Email, holder: &str) {
        let mut held = self.held.lock().await;
        if held.get(email).is_some_and(|(h, _)| h == holder) {
            held.remove(email);
        }
    }

    pub(crate) async fn is_locked(&self, email: &Email) -> bool {
        self.held
            .lock()
            .await
            .get(email)
            .is_some_and(|(_, expires)| *expires > Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use secrecy::Secret;

    use super::*;

    fn email() -> Email {
        Email::try_from(Secret::new("test@example.com".to_string())).unwrap()
    }

    #[tokio::test]
    async fn one_holder_at_a_time() {
        let locks = UserLocks::default();
        assert!(locks.try_lock(&email(), "a", 10).await);
        assert!(!locks.try_lock(&email(), "b", 10).await);
        assert!(locks.is_locked(&email()).await);

        // Only the holder can release it.
        locks.unlock(&email(), "b").await;
        assert!(locks.is_locked(&email()).await);
        locks.unlock(&email(), "a").await;
        assert!(!locks.is_locked(&email()).await);
        assert!(locks.try_lock(&email(), "b", 10).await);
    }

    #[tokio::test(start_paused = true)]
    async fn an_abandoned_lock_expires() {
        let locks = UserLocks::default();
        assert!(locks.try_lock(&email(), "crashed", 10).await);

        tokio::time::advance(Duration::from_secs(11)).await;
        assert!(!locks.is_locked(&email()).await);
        assert!(locks.try_lock(&email(), "next", 10).await);

        // The late release of the expired holder leaves the new lock alone.
        locks.unlock(&email(), "crashed").await;
        assert!(locks.is_locked(&email()).await);
    }
}
