use std::sync::Arc;

use redis::Commands;
use secrecy::{ExposeSecret, Secret};
use tokio::sync::RwLock;

use tempered_core::{
    Email, PasswordResetToken, PasswordResetTokenStore, PasswordResetTokenStoreError,
};

use super::redis_support::user_key;

const ONE_HOUR_IN_SECONDS: u64 = 3600;
const RESET_TOKEN_PREFIX: &str = "password_reset:";
const PENDING_PREFIX: &str = "password_reset_pending:";

/// Redis-backed [`PasswordResetTokenStore`].
///
/// - `password_reset:{token}` → the address, expiring after an hour,
///   consumed with `GETDEL`;
/// - `password_reset_pending:{email}` → that address's outstanding tokens,
///   so [`delete_all_for_user`](PasswordResetTokenStore::delete_all_for_user)
///   can drop them. A member whose token already expired is harmless; the
///   set expires with the newest token.
#[derive(Clone)]
pub struct RedisPasswordResetTokenStore {
    client: Arc<RwLock<redis::Connection>>,
}

impl RedisPasswordResetTokenStore {
    pub fn new(client: Arc<RwLock<redis::Connection>>) -> Self {
        Self { client }
    }
}

fn unexpected(e: impl std::fmt::Display) -> PasswordResetTokenStoreError {
    PasswordResetTokenStoreError::UnexpectedError(e.to_string())
}

fn parse_email(value: Option<String>) -> Result<Email, PasswordResetTokenStoreError> {
    let value = value.ok_or(PasswordResetTokenStoreError::TokenNotFound)?;
    Email::try_from(Secret::new(value)).map_err(unexpected)
}

#[async_trait::async_trait]
impl PasswordResetTokenStore for RedisPasswordResetTokenStore {
    async fn store_token(
        &self,
        token: PasswordResetToken,
        email: Email,
    ) -> Result<(), PasswordResetTokenStoreError> {
        let pending = user_key(PENDING_PREFIX, &email);
        redis::pipe()
            .atomic()
            .set_ex(
                get_key(&token),
                email.as_ref().expose_secret(),
                ONE_HOUR_IN_SECONDS,
            )
            .ignore()
            .sadd(&pending, token.to_string())
            .ignore()
            .expire(&pending, ONE_HOUR_IN_SECONDS as i64)
            .ignore()
            .query::<()>(&mut *self.client.write().await)
            .map_err(unexpected)
    }

    async fn get_email_for_token(
        &self,
        token: &PasswordResetToken,
    ) -> Result<Email, PasswordResetTokenStoreError> {
        let value: Option<String> = self
            .client
            .write()
            .await
            .get(get_key(token))
            .map_err(unexpected)?;
        parse_email(value)
    }

    async fn delete_token(
        &self,
        token: &PasswordResetToken,
    ) -> Result<(), PasswordResetTokenStoreError> {
        self.consume_token(token).await.map(|_| ())
    }

    async fn consume_token(
        &self,
        token: &PasswordResetToken,
    ) -> Result<Email, PasswordResetTokenStoreError> {
        let mut client = self.client.write().await;
        // GETDEL is a single Redis command, so redeeming is atomic even
        // across multiple service instances.
        let value: Option<String> = client.get_del(get_key(token)).map_err(unexpected)?;
        let email = parse_email(value)?;
        let _: i64 = client
            .srem(user_key(PENDING_PREFIX, &email), token.to_string())
            .map_err(unexpected)?;
        Ok(email)
    }

    async fn delete_all_for_user(&self, email: &Email) -> Result<(), PasswordResetTokenStoreError> {
        let mut client = self.client.write().await;
        let pending = user_key(PENDING_PREFIX, email);
        let tokens: Vec<String> = client.smembers(&pending).map_err(unexpected)?;
        let mut pipe = redis::pipe();
        pipe.atomic();
        for token in &tokens {
            pipe.del(format!("{RESET_TOKEN_PREFIX}{token}")).ignore();
        }
        pipe.del(&pending).ignore();
        pipe.query::<()>(&mut *client).map_err(unexpected)
    }
}

fn get_key(token: &PasswordResetToken) -> String {
    format!("{}{}", RESET_TOKEN_PREFIX, token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{contract, test_support};

    #[tokio::test]
    async fn meets_the_password_reset_token_store_contract() {
        let (_redis, connection) = test_support::redis::connection().await;
        contract::password_reset_token_store(RedisPasswordResetTokenStore::new(connection)).await;
    }
}
