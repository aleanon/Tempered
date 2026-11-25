use redis::{AsyncCommands, aio::ConnectionManager};
use secrecy::ExposeSecret;
use tempered_core::{Email, TwoFaAttemptId, TwoFaCode, TwoFaCodeStore, TwoFaCodeStoreError};

/// Redis-backed [`TwoFaCodeStore`].
///
/// - `two_fa_code:{email}` → a hash of the login attempt id and the code,
///   expiring with the code (an expired code reads as absent, so it fails
///   with `UserNotFound`);
/// - `two_fa_attempts:{email}` → failed codes in the current window. It
///   expires a window after the first failure and is not reset by a new
///   code, so logging in again does not buy more guesses.
///
/// [`redeem_code`](TwoFaCodeStore::redeem_code) runs as one Lua script:
/// the cap check, the comparison, the count and the consume cannot
/// interleave with another request, on this instance or any other.
#[derive(Clone)]
pub struct RedisTwoFaCodeStore {
    client: ConnectionManager,
    max_attempts: u32,
    /// Prefix before every key; empty by default.
    namespace: std::sync::Arc<str>,
}

impl RedisTwoFaCodeStore {
    /// Default limits: 5 failed codes per 10 minutes, codes live 10 minutes.
    pub fn new(client: ConnectionManager) -> Self {
        Self::with_max_attempts(client, DEFAULT_MAX_ATTEMPTS)
    }

    pub fn with_max_attempts(client: ConnectionManager, max_attempts: u32) -> Self {
        Self {
            client,
            max_attempts,
            namespace: "".into(),
        }
    }

    /// Keep this store's codes and counters under `{namespace}:`, apart from
    /// any other code store on the server (passwordless email login needs a
    /// store of its own).
    pub fn with_namespace(mut self, namespace: &str) -> Self {
        self.namespace = if namespace.is_empty() {
            "".into()
        } else {
            format!("{namespace}:").into()
        };
        self
    }

    fn get_key(&self, email: &Email) -> String {
        format!(
            "{}{TWO_FA_CODE_PREFIX}{}",
            self.namespace,
            email.as_ref().expose_secret()
        )
    }

    fn get_attempts_key(&self, email: &Email) -> String {
        format!(
            "{}{TWO_FA_ATTEMPTS_PREFIX}{}",
            self.namespace,
            email.as_ref().expose_secret()
        )
    }
}

fn unexpected(e: impl std::fmt::Display) -> TwoFaCodeStoreError {
    TwoFaCodeStoreError::UnexpectedError(e.to_string())
}

/// KEYS: code hash, attempts counter.
/// ARGV: attempt id, code, max attempts, window seconds.
const REDEEM_SCRIPT: &str = r"
local max = tonumber(ARGV[3])
local failed = tonumber(redis.call('get', KEYS[2]) or '0')
if failed >= max then
    redis.call('del', KEYS[1])
    return 'too_many'
end
local stored = redis.call('hmget', KEYS[1], 'attempt', 'code')
if not stored[1] then
    return 'missing'
end
if stored[1] ~= ARGV[1] then
    return 'wrong_attempt'
end
if stored[2] ~= ARGV[2] then
    failed = redis.call('incr', KEYS[2])
    if failed == 1 then
        redis.call('expire', KEYS[2], ARGV[4])
    end
    if failed >= max then
        redis.call('del', KEYS[1])
        return 'too_many'
    end
    return 'wrong_code'
end
redis.call('del', KEYS[1], KEYS[2])
return 'ok'
";

#[async_trait::async_trait]
impl TwoFaCodeStore for RedisTwoFaCodeStore {
    async fn store_code(
        &self,
        user_id: Email,
        login_attempt_id: TwoFaAttemptId,
        two_fa_code: TwoFaCode,
    ) -> Result<(), TwoFaCodeStoreError> {
        let key = self.get_key(&user_id);
        // The attempts counter is left alone: a new code is not a new budget.
        redis::pipe()
            .atomic()
            .del(&key)
            .ignore()
            .hset_multiple(
                &key,
                &[
                    ("attempt", login_attempt_id.to_string()),
                    ("code", two_fa_code.as_str().to_string()),
                ],
            )
            .ignore()
            .expire(&key, TEN_MINUTES_IN_SECONDS as i64)
            .ignore()
            .query_async::<()>(&mut self.client.clone())
            .await
            .map_err(unexpected)
    }

    async fn redeem_code(
        &self,
        user_id: &Email,
        login_attempt_id: &TwoFaAttemptId,
        two_fa_code: &TwoFaCode,
    ) -> Result<(), TwoFaCodeStoreError> {
        let outcome: String = redis::Script::new(REDEEM_SCRIPT)
            .key(self.get_key(user_id))
            .key(self.get_attempts_key(user_id))
            .arg(login_attempt_id.to_string())
            .arg(two_fa_code.as_str())
            .arg(self.max_attempts)
            .arg(TEN_MINUTES_IN_SECONDS)
            .invoke_async(&mut self.client.clone())
            .await
            .map_err(unexpected)?;
        match outcome.as_str() {
            "ok" => Ok(()),
            "missing" => Err(TwoFaCodeStoreError::UserNotFound),
            "wrong_attempt" => Err(TwoFaCodeStoreError::InvalidAttemptId),
            "wrong_code" => Err(TwoFaCodeStoreError::Invalid2FACode),
            "too_many" => Err(TwoFaCodeStoreError::TooManyAttempts),
            other => Err(unexpected(format!("unexpected script reply {other:?}"))),
        }
    }

    async fn get_login_attempt_id_and_two_fa_code(
        &self,
        user_id: &Email,
    ) -> Result<(TwoFaAttemptId, TwoFaCode), TwoFaCodeStoreError> {
        let (attempt, code): (Option<String>, Option<String>) = redis::cmd("HMGET")
            .arg(self.get_key(user_id))
            .arg("attempt")
            .arg("code")
            .query_async(&mut self.client.clone())
            .await
            .map_err(unexpected)?;
        let (Some(attempt), Some(code)) = (attempt, code) else {
            return Err(TwoFaCodeStoreError::UserNotFound);
        };
        let attempt = TwoFaAttemptId::parse(&attempt)
            .map_err(|e| unexpected(format!("stored attempt id: {e}")))?;
        let code = TwoFaCode::parse(code).map_err(|e| unexpected(format!("stored code: {e}")))?;
        Ok((attempt, code))
    }

    async fn delete(&self, user_id: &Email) -> Result<(), TwoFaCodeStoreError> {
        let removed: i64 = self
            .client
            .clone()
            .del(self.get_key(user_id))
            .await
            .map_err(unexpected)?;
        if removed == 0 {
            return Err(TwoFaCodeStoreError::UserNotFound);
        }
        Ok(())
    }
}

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const DEFAULT_MAX_ATTEMPTS: u32 = 5;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";
const TWO_FA_ATTEMPTS_PREFIX: &str = "two_fa_attempts:";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{contract, test_support};

    #[tokio::test]
    async fn meets_the_two_fa_code_store_contract() {
        let (_redis, connection) = test_support::redis::connection().await;
        contract::two_fa_code_store(RedisTwoFaCodeStore::new(connection)).await;
    }
}
