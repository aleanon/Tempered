use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use secrecy::{ExposeSecret, Secret};
use tempered_core::{Email, RecoveryCodeHash, TotpStore, TotpStoreError};

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
    users: Arc<Mutex<HashMap<Email, Entry>>>,
}

impl HashMapTotpStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn with<T>(&self, f: impl FnOnce(&mut HashMap<Email, Entry>) -> T) -> T {
        f(&mut self.users.lock().expect("TOTP map poisoned"))
    }
}

#[async_trait::async_trait]
impl TotpStore for HashMapTotpStore {
    async fn set_pending(
        &self,
        email: &Email,
        secret: Secret<Vec<u8>>,
    ) -> Result<(), TotpStoreError> {
        self.with(|u| {
            u.entry(email.clone()).or_default().pending = Some(secret.expose_secret().clone())
        });
        Ok(())
    }

    async fn pending(&self, email: &Email) -> Result<Option<Secret<Vec<u8>>>, TotpStoreError> {
        Ok(self.with(|u| {
            u.get(email)
                .and_then(|e| e.pending.clone())
                .map(Secret::new)
        }))
    }

    async fn activate(
        &self,
        email: &Email,
        used_step: u64,
        recovery_codes: Vec<RecoveryCodeHash>,
    ) -> Result<bool, TotpStoreError> {
        Ok(self.with(|u| {
            let Some(entry) = u.get_mut(email) else {
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

    async fn active(&self, email: &Email) -> Result<Option<Secret<Vec<u8>>>, TotpStoreError> {
        Ok(self.with(|u| u.get(email).and_then(|e| e.active.clone()).map(Secret::new)))
    }

    async fn use_step(&self, email: &Email, step: u64) -> Result<bool, TotpStoreError> {
        Ok(self.with(|u| {
            let Some(entry) = u.get_mut(email) else {
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
        email: &Email,
        recovery_codes: Vec<RecoveryCodeHash>,
    ) -> Result<(), TotpStoreError> {
        self.with(|u| {
            u.entry(email.clone()).or_default().recovery = recovery_codes.into_iter().collect()
        });
        Ok(())
    }

    async fn use_recovery_code(
        &self,
        email: &Email,
        code: &RecoveryCodeHash,
    ) -> Result<bool, TotpStoreError> {
        Ok(self.with(|u| u.get_mut(email).is_some_and(|e| e.recovery.remove(code))))
    }

    async fn delete_all_for_user(&self, email: &Email) -> Result<(), TotpStoreError> {
        self.with(|u| u.remove(email));
        Ok(())
    }

    async fn reassign(&self, old: &Email, new: &Email) -> Result<(), TotpStoreError> {
        self.with(|u| {
            if let Some(entry) = u.remove(old) {
                u.insert(new.clone(), entry);
            }
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn meets_the_totp_store_contract() {
        crate::persistence::contract::totp_store(HashMapTotpStore::new()).await;
    }
}
