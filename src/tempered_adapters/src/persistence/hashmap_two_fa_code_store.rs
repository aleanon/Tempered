use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use tempered_core::{Email, TwoFaAttemptId, TwoFaCode, TwoFaCodeStore, TwoFaCodeStoreError};

const DEFAULT_MAX_ATTEMPTS: u32 = 5;
const DEFAULT_TTL: Duration = Duration::from_secs(600);

struct StoredCode {
    attempt_id: TwoFaAttemptId,
    code: TwoFaCode,
    issued_at: Instant,
}

/// Failed codes for one account in the current window. Kept apart from the
/// code so that issuing a new code (logging in again) does not reset it.
struct Failures {
    count: u32,
    window_start: Instant,
}

#[derive(Default)]
struct State {
    codes: HashMap<Email, StoredCode>,
    failures: HashMap<Email, Failures>,
}

/// In-memory [`TwoFaCodeStore`] backed by a `HashMap`.
///
/// Enforces the trait's contract: codes expire after `ttl`, a correct code
/// is consumed, and an account gets `max_attempts` failed codes per `ttl`
/// window however many codes are issued in it.
///
/// # Warning: development and tests only
///
/// State is per-process and lost on restart. Use
/// [`RedisTwoFaCodeStore`](super::redis_two_fa_code_store::RedisTwoFaCodeStore)
/// in production.
#[derive(Clone)]
pub struct HashMapTwoFaCodeStore {
    state: Arc<RwLock<State>>,
    max_attempts: u32,
    ttl: Duration,
}

impl Default for HashMapTwoFaCodeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl HashMapTwoFaCodeStore {
    /// Default limits: 5 failed codes per 10 minutes, codes live 10 minutes.
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_ATTEMPTS, DEFAULT_TTL)
    }

    /// `ttl` is both how long a code lives and the failure-count window.
    pub fn with_limits(max_attempts: u32, ttl: Duration) -> Self {
        Self {
            state: Arc::new(RwLock::new(State::default())),
            max_attempts,
            ttl,
        }
    }
}

#[async_trait::async_trait]
impl TwoFaCodeStore for HashMapTwoFaCodeStore {
    /// Clones share their map; separate stores do not.
    fn keyspace(&self) -> Option<String> {
        Some(format!("memory:{:p}", Arc::as_ptr(&self.state)))
    }

    async fn store_code(
        &self,
        user_id: Email,
        login_attempt_id: TwoFaAttemptId,
        two_fa_code: TwoFaCode,
    ) -> Result<(), TwoFaCodeStoreError> {
        // The failure count is left alone: a new code is not a new budget.
        self.state.write().await.codes.insert(
            user_id,
            StoredCode {
                attempt_id: login_attempt_id,
                code: two_fa_code,
                issued_at: Instant::now(),
            },
        );
        Ok(())
    }

    async fn redeem_code(
        &self,
        user_id: &Email,
        login_attempt_id: &TwoFaAttemptId,
        two_fa_code: &TwoFaCode,
    ) -> Result<(), TwoFaCodeStoreError> {
        // One write lock for the whole check: comparing, counting and
        // consuming happen as one step.
        let mut state = self.state.write().await;
        let State { codes, failures } = &mut *state;

        if let Some(f) = failures.get(user_id)
            && f.window_start.elapsed() > self.ttl
        {
            failures.remove(user_id);
        }
        if failures
            .get(user_id)
            .is_some_and(|f| f.count >= self.max_attempts)
        {
            codes.remove(user_id);
            return Err(TwoFaCodeStoreError::TooManyAttempts);
        }

        let Some(stored) = codes.get(user_id) else {
            return Err(TwoFaCodeStoreError::UserNotFound);
        };
        if stored.issued_at.elapsed() > self.ttl {
            codes.remove(user_id);
            return Err(TwoFaCodeStoreError::CodeExpired);
        }
        if stored.attempt_id != *login_attempt_id {
            return Err(TwoFaCodeStoreError::InvalidAttemptId);
        }
        if stored.code != *two_fa_code {
            let f = failures.entry(user_id.clone()).or_insert(Failures {
                count: 0,
                window_start: Instant::now(),
            });
            f.count += 1;
            if f.count >= self.max_attempts {
                codes.remove(user_id);
                return Err(TwoFaCodeStoreError::TooManyAttempts);
            }
            return Err(TwoFaCodeStoreError::Invalid2FACode);
        }

        codes.remove(user_id);
        failures.remove(user_id);
        Ok(())
    }

    async fn get_login_attempt_id_and_two_fa_code(
        &self,
        user_id: &Email,
    ) -> Result<(TwoFaAttemptId, TwoFaCode), TwoFaCodeStoreError> {
        let state = self.state.read().await;
        let Some(stored) = state.codes.get(user_id) else {
            return Err(TwoFaCodeStoreError::UserNotFound);
        };
        Ok((stored.attempt_id.clone(), stored.code.clone()))
    }

    async fn delete(&self, user_id: &Email) -> Result<(), TwoFaCodeStoreError> {
        self.state
            .write()
            .await
            .codes
            .remove(user_id)
            .ok_or(TwoFaCodeStoreError::UserNotFound)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use secrecy::Secret;

    use super::*;
    use crate::persistence::contract;

    fn email() -> Email {
        Email::try_from(Secret::new("test@example.com".to_string())).unwrap()
    }

    #[tokio::test]
    async fn meets_the_two_fa_code_store_contract() {
        contract::two_fa_code_store(HashMapTwoFaCodeStore::new()).await;
    }

    #[tokio::test]
    async fn expires_codes_past_the_ttl() {
        let store = HashMapTwoFaCodeStore::with_limits(5, Duration::from_secs(0));
        let (attempt_id, code) = (TwoFaAttemptId::default(), TwoFaCode::new());
        store
            .store_code(email(), attempt_id.clone(), code.clone())
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(5)).await;
        let err = store.redeem_code(&email(), &attempt_id, &code).await;
        assert_eq!(err, Err(TwoFaCodeStoreError::CodeExpired));
    }
}
