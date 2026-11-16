use std::sync::Arc;

use redis::Commands;
use secrecy::ExposeSecret;
use tempered_core::{Email, TwoFaAttemptId, TwoFaCode, TwoFaCodeStore, TwoFaCodeStoreError};
use tokio::sync::RwLock;

/// Redis-backed [`TwoFaCodeStore`].
///
/// Enforces the trait's guessing-budget contract: the code key carries a TTL
/// (expiry surfaces as `UserNotFound` → treated as an invalid/expired code by
/// the handler), and failed attempts are counted in a sibling
/// `two_fa_attempts:` key via atomic `INCR`, so the cap holds across
/// concurrent requests and multiple service instances.
#[derive(Clone)]
pub struct RedisTwoFaCodeStore {
    client: Arc<RwLock<redis::Connection>>,
    max_attempts: u32,
}

impl RedisTwoFaCodeStore {
    /// Default limit: 5 attempts (codes expire after 10 minutes).
    pub fn new(client: Arc<RwLock<redis::Connection>>) -> Self {
        Self::with_max_attempts(client, DEFAULT_MAX_ATTEMPTS)
    }

    pub fn with_max_attempts(client: Arc<RwLock<redis::Connection>>, max_attempts: u32) -> Self {
        Self {
            client,
            max_attempts,
        }
    }
}

#[async_trait::async_trait]
impl TwoFaCodeStore for RedisTwoFaCodeStore {
    async fn store_code(
        &self,
        user_id: Email,
        login_attempt_id: TwoFaAttemptId,
        two_fa_code: TwoFaCode,
    ) -> Result<(), TwoFaCodeStoreError> {
        let key = get_key(&user_id);

        let value = serde_json::to_string(&(login_attempt_id, two_fa_code))
            .map_err(|e| TwoFaCodeStoreError::UnexpectedError(e.to_string()))?;

        let mut client = self.client.write().await;
        let _: () = client
            .set_ex(key, value, TEN_MINUTES_IN_SECONDS)
            .map_err(|e| TwoFaCodeStoreError::UnexpectedError(e.to_string()))?;
        // A fresh code resets the guessing budget.
        client
            .del(get_attempts_key(&user_id))
            .map_err(|e| TwoFaCodeStoreError::UnexpectedError(e.to_string()))
    }

    async fn validate(
        &self,
        user_id: &Email,
        login_attempt_id: &TwoFaAttemptId,
        two_fa_code: &TwoFaCode,
    ) -> Result<(), TwoFaCodeStoreError> {
        let (stored_login_attempt_id, stored_two_fa_code) =
            self.get_login_attempt_id_and_two_fa_code(user_id).await?;

        if stored_login_attempt_id != *login_attempt_id {
            return Err(TwoFaCodeStoreError::InvalidAttemptId);
        }
        if stored_two_fa_code != *two_fa_code {
            // Count the failure atomically (INCR), bounded to the code's own
            // lifetime (EXPIRE), so parallel guesses across instances all hit
            // the same budget.
            let attempts_key = get_attempts_key(user_id);
            let mut client = self.client.write().await;
            let attempts: u32 = client
                .incr(&attempts_key, 1)
                .map_err(|e| TwoFaCodeStoreError::UnexpectedError(e.to_string()))?;
            let _: () = client
                .expire(&attempts_key, TEN_MINUTES_IN_SECONDS as i64)
                .map_err(|e| TwoFaCodeStoreError::UnexpectedError(e.to_string()))?;

            if attempts >= self.max_attempts {
                let _: Result<(), _> = client.del(get_key(user_id));
                let _: Result<(), _> = client.del(&attempts_key);
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
        let key = get_key(user_id);

        let json_value: String = self
            .client
            .write()
            .await
            .get(key)
            .map_err(|_| TwoFaCodeStoreError::UserNotFound)?;

        let (login_attempt_id, two_fa_code): (TwoFaAttemptId, TwoFaCode) =
            serde_json::from_str(&json_value)
                .map_err(|e| TwoFaCodeStoreError::UnexpectedError(e.to_string()))?;

        Ok((login_attempt_id, two_fa_code))
    }

    async fn delete(&self, user_id: &Email) -> Result<(), TwoFaCodeStoreError> {
        let key = get_key(user_id);

        self.client
            .write()
            .await
            .del(key)
            .map_err(|_| TwoFaCodeStoreError::UserNotFound)
    }
}

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const DEFAULT_MAX_ATTEMPTS: u32 = 5;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";
const TWO_FA_ATTEMPTS_PREFIX: &str = "two_fa_attempts:";

fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref().expose_secret())
}

fn get_attempts_key(email: &Email) -> String {
    format!(
        "{}{}",
        TWO_FA_ATTEMPTS_PREFIX,
        email.as_ref().expose_secret()
    )
}
