use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use secrecy::{ExposeSecret, Secret};
use tempered_core::{RecoveryCodeHash, TotpStore, TotpStoreError, UserId};

#[derive(Default)]
struct Entry {
    pending: Option<Vec<u8>>,
    active: Option<Vec<u8>>,
    last_step: Option<u64>,
    recovery: HashSet<RecoveryCodeHash>,
}

/// In-memory [`TotpStore`].
///
/// # Warning: development and tests only
///
/// Secrets are lost on restart, so every enrolled authenticator stops
/// working. Use
/// [`PostgresTotpStore`](super::postgres_totp_store::PostgresTotpStore) in
/// production.
#[derive(Default, Clone)]
pub struct HashMapTotpStore {
    users: Arc<Mutex<HashMap<UserId, Entry>>>,
}

impl HashMapTotpStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn with<T>(&self, f: impl FnOnce(&mut HashMap<UserId, Entry>) -> T) -> T {
        f(&mut self.users.lock().expect("TOTP map poisoned"))
    }
}

#[async_trait::async_trait]
impl TotpStore for HashMapTotpStore {
    async fn set_pending(
        &self,
        user: &UserId,
        secret: Secret<Vec<u8>>,
    ) -> Result<(), TotpStoreError> {
        self.with(|u| u.entry(*user).or_default().pending = Some(secret.expose_secret().clone()));
        Ok(())
    }

    async fn pending(&self, user: &UserId) -> Result<Option<Secret<Vec<u8>>>, TotpStoreError> {
        Ok(self.with(|u| u.get(user).and_then(|e| e.pending.clone()).map(Secret::new)))
    }

    async fn activate(
        &self,
        user: &UserId,
        used_step: u64,
        recovery_codes: Vec<RecoveryCodeHash>,
    ) -> Result<bool, TotpStoreError> {
        Ok(self.with(|u| {
            let Some(entry) = u.get_mut(user) else {
                return false;
            };
            let Some(pending) = entry.pending.take() else {
                return false;
            };
            entry.active = Some(pending);
            entry.last_step = Some(used_step);
            entry.recovery = recovery_codes.into_iter().collect();
            true
        }))
    }

    async fn active(&self, user: &UserId) -> Result<Option<Secret<Vec<u8>>>, TotpStoreError> {
        Ok(self.with(|u| u.get(user).and_then(|e| e.active.clone()).map(Secret::new)))
    }

    async fn use_step(&self, user: &UserId, step: u64) -> Result<bool, TotpStoreError> {
        Ok(self.with(|u| {
            let Some(entry) = u.get_mut(user) else {
                return false;
            };
            if entry.active.is_none() || entry.last_step.is_some_and(|last| step <= last) {
                return false;
            }
            entry.last_step = Some(step);
            true
        }))
    }

    async fn replace_recovery_codes(
        &self,
        user: &UserId,
        recovery_codes: Vec<RecoveryCodeHash>,
    ) -> Result<(), TotpStoreError> {
        self.with(|u| u.entry(*user).or_default().recovery = recovery_codes.into_iter().collect());
        Ok(())
    }

    async fn use_recovery_code(
        &self,
        user: &UserId,
        code: &RecoveryCodeHash,
    ) -> Result<bool, TotpStoreError> {
        Ok(self.with(|u| u.get_mut(user).is_some_and(|e| e.recovery.remove(code))))
    }

    async fn delete_all_for_user(&self, user: &UserId) -> Result<(), TotpStoreError> {
        self.with(|u| u.remove(user));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn meets_the_totp_store_contract() {
        crate::persistence::contract::totp_store(
            HashMapTotpStore::new(),
            [tempered_core::UserId::new(), tempered_core::UserId::new()],
        )
        .await;
    }
}
