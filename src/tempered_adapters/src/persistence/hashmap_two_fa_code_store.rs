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
    failed_attempts: u32,
}

/// In-memory [`TwoFaCodeStore`] backed by a `HashMap`.
///
/// Enforces the trait's guessing-budget contract: codes expire after `ttl`
/// and are deleted after `max_attempts` failed validations.
///
/// # Warning: development and tests only
///
/// State is per-process and lost on restart. Use
/// [`RedisTwoFaCodeStore`](super::redis_two_fa_code_store::RedisTwoFaCodeStore)
/// in production.
#[derive(Clone)]
pub struct HashMapTwoFaCodeStore {
    codes: Arc<RwLock<HashMap<Email, StoredCode>>>,
    max_attempts: u32,
    ttl: Duration,
}

impl Default for HashMapTwoFaCodeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl HashMapTwoFaCodeStore {
    /// Default limits: 5 attempts, 10-minute TTL.
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_ATTEMPTS, DEFAULT_TTL)
    }

    pub fn with_limits(max_attempts: u32, ttl: Duration) -> Self {
        Self {
            codes: Arc::new(RwLock::new(HashMap::new())),
            max_attempts,
            ttl,
        }
    }
}

#[async_trait::async_trait]
impl TwoFaCodeStore for HashMapTwoFaCodeStore {
    async fn store_code(
        &self,
        user_id: Email,
        login_attempt_id: TwoFaAttemptId,
        two_fa_code: TwoFaCode,
    ) -> Result<(), TwoFaCodeStoreError> {
        let mut codes = self.codes.write().await;
        codes.insert(
            user_id,
            StoredCode {
                attempt_id: login_attempt_id,
                code: two_fa_code,
                issued_at: Instant::now(),
                failed_attempts: 0,
            },
        );
        Ok(())
    }

    async fn validate(
        &self,
        user_id: &Email,
        login_attempt_id: &TwoFaAttemptId,
        two_fa_code: &TwoFaCode,
    ) -> Result<(), TwoFaCodeStoreError> {
        // Take the write lock for the whole check so the counter update is
        // atomic with the comparison (no parallel-guess window).
        let mut codes = self.codes.write().await;
        let Some(stored) = codes.get_mut(user_id) else {
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
            stored.failed_attempts += 1;
            if stored.failed_attempts >= self.max_attempts {
                codes.remove(user_id);
                return Err(TwoFaCodeStoreError::TooManyAttempts);
            }
            return Err(TwoFaCodeStoreError::Invalid2FACode);
        }
        Ok(())
    }

    async fn get_login_attempt_id_and_two_fa_code(
        &self,
        user_id: &Email,
    ) -> Result<(TwoFaAttemptId, TwoFaCode), TwoFaCodeStoreError> {
        let codes = self.codes.read().await;
        let Some(stored) = codes.get(user_id) else {
            return Err(TwoFaCodeStoreError::UserNotFound);
        };
        Ok((stored.attempt_id.clone(), stored.code.clone()))
    }

    async fn delete(&self, user_id: &Email) -> Result<(), TwoFaCodeStoreError> {
        let mut codes = self.codes.write().await;
        codes
            .remove(user_id)
            .ok_or(TwoFaCodeStoreError::UserNotFound)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use secrecy::Secret;

    use super::*;

    fn email() -> Email {
        Email::try_from(Secret::new("test@example.com".to_string())).unwrap()
    }

    fn wrong_code(right: &TwoFaCode) -> TwoFaCode {
        let flipped = if right.as_str() == "000000" {
            "000001"
        } else {
            "000000"
        };
        TwoFaCode::parse(flipped.to_string()).unwrap()
    }

    #[tokio::test]
    async fn caps_failed_attempts_and_deletes_the_code() {
        let store = HashMapTwoFaCodeStore::with_limits(3, Duration::from_secs(600));
        let (attempt_id, code) = (TwoFaAttemptId::default(), TwoFaCode::new());
        store
            .store_code(email(), attempt_id.clone(), code.clone())
            .await
            .unwrap();
        let wrong = wrong_code(&code);

        for _ in 0..2 {
            let err = store.validate(&email(), &attempt_id, &wrong).await;
            assert_eq!(err, Err(TwoFaCodeStoreError::Invalid2FACode));
        }
        let err = store.validate(&email(), &attempt_id, &wrong).await;
        assert_eq!(err, Err(TwoFaCodeStoreError::TooManyAttempts));

        // The code is gone — even the *correct* code no longer validates.
        let err = store.validate(&email(), &attempt_id, &code).await;
        assert_eq!(err, Err(TwoFaCodeStoreError::UserNotFound));
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
        let err = store.validate(&email(), &attempt_id, &code).await;
        assert_eq!(err, Err(TwoFaCodeStoreError::CodeExpired));
    }

    #[tokio::test]
    async fn correct_code_within_budget_validates() {
        let store = HashMapTwoFaCodeStore::new();
        let (attempt_id, code) = (TwoFaAttemptId::default(), TwoFaCode::new());
        store
            .store_code(email(), attempt_id.clone(), code.clone())
            .await
            .unwrap();

        let wrong = wrong_code(&code);
        let _ = store.validate(&email(), &attempt_id, &wrong).await;
        assert!(store.validate(&email(), &attempt_id, &code).await.is_ok());
    }
}
