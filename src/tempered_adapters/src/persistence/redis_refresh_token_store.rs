use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::{AsyncCommands, aio::ConnectionManager};
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};

use tempered_core::{
    Email, RefreshRecord, RefreshTokenHash, RefreshTokenStore, RefreshTokenStoreError,
};

use super::redis_support::user_key;

const TOKEN_PREFIX: &str = "refresh:";
const FAMILY_PREFIX: &str = "refresh_family:";
const USER_PREFIX: &str = "refresh_user:";

/// Redis-backed [`RefreshTokenStore`].
///
/// Keys:
/// - `refresh:{hash}` → the record and whether it was used, expiring with
///   the token (used tokens stay until then, so reuse is noticed);
/// - `refresh_family:{family}` → the set of the family's token hashes;
/// - `refresh_user:{email}` → the set of the user's families.
#[derive(Clone)]
pub struct RedisRefreshTokenStore {
    client: ConnectionManager,
}

impl RedisRefreshTokenStore {
    pub fn new(client: ConnectionManager) -> Self {
        Self { client }
    }
}

#[derive(Serialize, Deserialize)]
struct Stored {
    email: String,
    family: String,
    expires_at: u64,
}

/// Mark `KEYS[1]` used if it is unused (`ARGV[1]` = now): returns `{0, value}`
/// for a fresh token, `{1, value}` for a reused one (whose family the caller
/// revokes), or nil. One script, so two requests with one token cannot both
/// see it unused.
static REDEEM_SCRIPT: std::sync::LazyLock<redis::Script> = std::sync::LazyLock::new(|| {
    redis::Script::new(
        r"
        local value = redis.call('HGET', KEYS[1], 'record')
        if not value then return false end
        if redis.call('HGET', KEYS[1], 'used') == '1' then return {1, value} end
        redis.call('HSET', KEYS[1], 'used', '1')
        return {0, value}
        ",
    )
});

fn unexpected(e: impl std::fmt::Display) -> RefreshTokenStoreError {
    RefreshTokenStoreError::UnexpectedError(e.to_string())
}

fn token_key(token: &RefreshTokenHash) -> String {
    format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(token))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl RedisRefreshTokenStore {
    async fn revoke_family(&self, family: &str) -> Result<(), RefreshTokenStoreError> {
        let mut client = self.client.clone();
        let set = format!("{FAMILY_PREFIX}{family}");
        let members: Vec<String> = client.smembers(&set).await.map_err(unexpected)?;
        let mut pipe = redis::pipe();
        pipe.atomic();
        for member in &members {
            pipe.del(format!("{TOKEN_PREFIX}{member}")).ignore();
        }
        pipe.del(&set).ignore();
        pipe.query_async::<()>(&mut client)
            .await
            .map_err(unexpected)
    }
}

#[async_trait::async_trait]
impl RefreshTokenStore for RedisRefreshTokenStore {
    async fn create(
        &self,
        token: RefreshTokenHash,
        record: RefreshRecord,
    ) -> Result<(), RefreshTokenStoreError> {
        let ttl = record.expires_at.saturating_sub(now()).max(1) as i64;
        let value = serde_json::to_string(&Stored {
            email: record.email.as_ref().expose_secret().clone(),
            family: record.family.clone(),
            expires_at: record.expires_at,
        })
        .map_err(unexpected)?;
        let key = token_key(&token);
        let family = format!("{FAMILY_PREFIX}{}", record.family);
        let user = user_key(USER_PREFIX, &record.email);
        redis::pipe()
            .atomic()
            .hset_multiple(&key, &[("record", value.as_str()), ("used", "0")])
            .ignore()
            .expire(&key, ttl)
            .ignore()
            .sadd(&family, URL_SAFE_NO_PAD.encode(token))
            .ignore()
            .expire(&family, ttl)
            .ignore()
            .sadd(&user, &record.family)
            .ignore()
            .expire(&user, ttl)
            .ignore()
            .query_async::<()>(&mut self.client.clone())
            .await
            .map_err(unexpected)
    }

    async fn redeem(
        &self,
        token: &RefreshTokenHash,
    ) -> Result<RefreshRecord, RefreshTokenStoreError> {
        let result: Option<(u8, String)> = REDEEM_SCRIPT
            .key(token_key(token))
            .invoke_async(&mut self.client.clone())
            .await
            .map_err(unexpected)?;
        let (reused, value) = result.ok_or(RefreshTokenStoreError::NotFound)?;
        let stored: Stored = serde_json::from_str(&value).map_err(unexpected)?;
        let email = Email::try_from(Secret::new(stored.email)).map_err(unexpected)?;
        if stored.expires_at <= now() {
            return Err(RefreshTokenStoreError::NotFound);
        }
        if reused == 1 {
            self.revoke_family(&stored.family).await?;
            return Err(RefreshTokenStoreError::Reused { email });
        }
        Ok(RefreshRecord {
            email,
            family: stored.family,
            expires_at: stored.expires_at,
        })
    }

    async fn revoke_family_of(
        &self,
        token: &RefreshTokenHash,
    ) -> Result<(), RefreshTokenStoreError> {
        let value: Option<String> = self
            .client
            .clone()
            .hget(token_key(token), "record")
            .await
            .map_err(unexpected)?;
        match value {
            Some(value) => {
                let stored: Stored = serde_json::from_str(&value).map_err(unexpected)?;
                self.revoke_family(&stored.family).await
            }
            None => Ok(()),
        }
    }

    async fn revoke_all_for_user(&self, email: &Email) -> Result<(), RefreshTokenStoreError> {
        let user = user_key(USER_PREFIX, email);
        let families: Vec<String> = self
            .client
            .clone()
            .smembers(&user)
            .await
            .map_err(unexpected)?;
        for family in families {
            self.revoke_family(&family).await?;
        }
        let _: () = self.client.clone().del(&user).await.map_err(unexpected)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{contract, test_support};

    #[tokio::test]
    async fn meets_the_refresh_token_store_contract() {
        let (_redis, connection) = test_support::redis::connection().await;
        contract::refresh_token_store(RedisRefreshTokenStore::new(connection)).await;
    }
}
