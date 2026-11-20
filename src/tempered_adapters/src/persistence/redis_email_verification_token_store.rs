use std::sync::Arc;

use redis::Commands;
use secrecy::{ExposeSecret, Secret};
use tokio::sync::RwLock;

use tempered_core::{
    Email, EmailVerificationStoreError, EmailVerificationToken, EmailVerificationTokenStore,
};

use super::redis_support::user_key;

const TOKEN_PREFIX: &str = "email_verification:";
const PENDING_PREFIX: &str = "email_verification_pending:";
const VERIFIED_PREFIX: &str = "email_verified:";

/// Redis-backed [`EmailVerificationTokenStore`].
///
/// - `email_verification:{token}` → the address, expiring after
///   `token_ttl_seconds` (a day is common), consumed with `GETDEL`;
/// - `email_verification_pending:{email}` → that address's pending tokens,
///   so [`forget_email`](EmailVerificationTokenStore::forget_email) can drop
///   them;
/// - `email_verified:{email}` → the verified mark. It never expires, so this
///   Redis must be persistent (AOF or RDB): a lost mark un-verifies the
///   address, which locks the user out of verified routes until they verify
///   again and makes their account count as unproven on a first provider
///   login.
#[derive(Clone)]
pub struct RedisEmailVerificationTokenStore {
    client: Arc<RwLock<redis::Connection>>,
    token_ttl_seconds: u64,
}

impl RedisEmailVerificationTokenStore {
    pub fn new(client: Arc<RwLock<redis::Connection>>, token_ttl_seconds: u64) -> Self {
        Self {
            client,
            token_ttl_seconds,
        }
    }
}

fn unexpected(e: impl std::fmt::Display) -> EmailVerificationStoreError {
    EmailVerificationStoreError::UnexpectedError(e.to_string())
}

fn token_key(token: &str) -> String {
    format!("{TOKEN_PREFIX}{token}")
}

#[async_trait::async_trait]
impl EmailVerificationTokenStore for RedisEmailVerificationTokenStore {
    async fn store_pending_verification(
        &self,
        token: EmailVerificationToken,
        email: Email,
    ) -> Result<(), EmailVerificationStoreError> {
        let pending = user_key(PENDING_PREFIX, &email);
        redis::pipe()
            .atomic()
            .set_ex(
                token_key(&token.to_string()),
                email.as_ref().expose_secret(),
                self.token_ttl_seconds,
            )
            .ignore()
            .sadd(&pending, token.to_string())
            .ignore()
            .expire(&pending, self.token_ttl_seconds as i64)
            .ignore()
            .query::<()>(&mut *self.client.write().await)
            .map_err(unexpected)
    }

    async fn consume_token(
        &self,
        token: &EmailVerificationToken,
    ) -> Result<Email, EmailVerificationStoreError> {
        let mut client = self.client.write().await;
        let value: Option<String> = client
            .get_del(token_key(&token.to_string()))
            .map_err(unexpected)?;
        let email = Email::try_from(Secret::new(
            value.ok_or(EmailVerificationStoreError::TokenNotFound)?,
        ))
        .map_err(unexpected)?;
        let _: i64 = client
            .srem(user_key(PENDING_PREFIX, &email), token.to_string())
            .map_err(unexpected)?;
        Ok(email)
    }

    async fn mark_verified(&self, email: &Email) -> Result<(), EmailVerificationStoreError> {
        self.client
            .write()
            .await
            .set(user_key(VERIFIED_PREFIX, email), 1)
            .map_err(unexpected)
    }

    async fn is_verified(&self, email: &Email) -> Result<bool, EmailVerificationStoreError> {
        self.client
            .write()
            .await
            .exists(user_key(VERIFIED_PREFIX, email))
            .map_err(unexpected)
    }

    async fn forget_email(&self, email: &Email) -> Result<(), EmailVerificationStoreError> {
        let mut client = self.client.write().await;
        let pending = user_key(PENDING_PREFIX, email);
        let tokens: Vec<String> = client.smembers(&pending).map_err(unexpected)?;
        let mut pipe = redis::pipe();
        pipe.atomic();
        for token in &tokens {
            pipe.del(token_key(token)).ignore();
        }
        pipe.del(&pending)
            .ignore()
            .del(user_key(VERIFIED_PREFIX, email))
            .ignore();
        pipe.query::<()>(&mut *client).map_err(unexpected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{contract, test_support};

    #[tokio::test]
    async fn meets_the_email_verification_token_store_contract() {
        let (_redis, connection) = test_support::redis::connection().await;
        contract::email_verification_token_store(RedisEmailVerificationTokenStore::new(
            connection, 86_400,
        ))
        .await;
    }
}
