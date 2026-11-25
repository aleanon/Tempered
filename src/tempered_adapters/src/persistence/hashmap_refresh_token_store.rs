use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tempered_core::{
    Email, RefreshRecord, RefreshTokenHash, RefreshTokenStore, RefreshTokenStoreError,
};

#[derive(Default)]
struct State {
    /// token → (record, used).
    tokens: HashMap<RefreshTokenHash, (RefreshRecord, bool)>,
    /// Revoked families: no new token joins one.
    revoked: std::collections::HashSet<String>,
}

impl State {
    fn revoke(&mut self, family: &str) {
        self.tokens.retain(|_, (r, _)| r.family != family);
        self.revoked.insert(family.to_string());
    }
}

/// In-memory [`RefreshTokenStore`].
///
/// # Warning: development and tests only
///
/// Tokens are lost on restart (every client must log in again) and are
/// per process. Use
/// [`RedisRefreshTokenStore`](super::redis_refresh_token_store::RedisRefreshTokenStore)
/// in production.
#[derive(Default, Clone)]
pub struct HashMapRefreshTokenStore {
    state: Arc<Mutex<State>>,
}

impl HashMapRefreshTokenStore {
    pub fn new() -> Self {
        Self::default()
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[async_trait::async_trait]
impl RefreshTokenStore for HashMapRefreshTokenStore {
    async fn create(
        &self,
        token: RefreshTokenHash,
        record: RefreshRecord,
    ) -> Result<(), RefreshTokenStoreError> {
        let mut state = self.state.lock().expect("refresh map poisoned");
        if state.revoked.contains(&record.family) {
            return Err(RefreshTokenStoreError::NotFound);
        }
        let now = now();
        state.tokens.retain(|_, (r, _)| r.expires_at > now);
        state.tokens.insert(token, (record, false));
        Ok(())
    }

    async fn redeem(
        &self,
        token: &RefreshTokenHash,
    ) -> Result<RefreshRecord, RefreshTokenStoreError> {
        let mut state = self.state.lock().expect("refresh map poisoned");
        let Some((record, used)) = state.tokens.get_mut(token) else {
            return Err(RefreshTokenStoreError::NotFound);
        };
        if record.expires_at <= now() {
            return Err(RefreshTokenStoreError::NotFound);
        }
        if *used {
            let (family, email) = (record.family.clone(), record.email.clone());
            state.revoke(&family);
            return Err(RefreshTokenStoreError::Reused { email });
        }
        *used = true;
        Ok(record.clone())
    }

    async fn revoke_family(&self, family: &str) -> Result<(), RefreshTokenStoreError> {
        self.state
            .lock()
            .expect("refresh map poisoned")
            .revoke(family);
        Ok(())
    }

    async fn revoke_all_for_user(&self, email: &Email) -> Result<(), RefreshTokenStoreError> {
        let mut state = self.state.lock().expect("refresh map poisoned");
        let families: Vec<String> = state
            .tokens
            .values()
            .filter(|(r, _)| &r.email == email)
            .map(|(r, _)| r.family.clone())
            .collect();
        for family in families {
            state.revoke(&family);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn meets_the_refresh_token_store_contract() {
        crate::persistence::contract::refresh_token_store(HashMapRefreshTokenStore::new()).await;
    }
}
