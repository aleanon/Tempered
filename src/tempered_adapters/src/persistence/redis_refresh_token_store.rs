use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::aio::ConnectionManager;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};

use tempered_core::{
    Email, RefreshRecord, RefreshTokenHash, RefreshTokenStore, RefreshTokenStoreError,
};

use super::redis_support::user_key;

const TOKEN_PREFIX: &str = "refresh:";
const FAMILY_PREFIX: &str = "refresh_family:";
const REVOKED_PREFIX: &str = "refresh_revoked:";
const USER_PREFIX: &str = "refresh_user:";

/// How long a revoked family refuses new tokens. Only a rotation already
/// in flight at the revocation can try to add one, so seconds would do.
const TOMBSTONE_SECONDS: u64 = 60 * 60;

/// Redis-backed [`RefreshTokenStore`].
///
/// Keys:
/// - `refresh:{hash}` → the record and whether it was used, expiring with
///   the token (used tokens stay until then, so reuse is noticed);
/// - `refresh_family:{family}` → the set of the family's token hashes;
/// - `refresh_revoked:{family}` → present for an hour after a revocation,
///   so a rotation in flight cannot bring the family back;
/// - `refresh_user:{email}` → the set of the user's families.
///
/// The sets expire with the longest-lived token they index: a new token
/// only ever extends a set's lifetime, never shortens it, so a revoke-all
/// reaches every family that can still be redeemed. Every operation that
/// touches more than one key is one Lua script.
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
    user_id: tempered_core::UserId,
    family: String,
    expires_at: u64,
}

/// `KEYS`: token, family set, tombstone, user set. `ARGV`: record JSON,
/// TTL, token id (base64), family. Returns 0 if the family is revoked
/// (nothing written), 1 otherwise.
static CREATE_SCRIPT: std::sync::LazyLock<redis::Script> = std::sync::LazyLock::new(|| {
    redis::Script::new(
        r"
        if redis.call('EXISTS', KEYS[3]) == 1 then return 0 end
        local ttl = tonumber(ARGV[2])
        redis.call('HSET', KEYS[1], 'record', ARGV[1], 'used', '0')
        redis.call('EXPIRE', KEYS[1], ttl)
        redis.call('SADD', KEYS[2], ARGV[3])
        redis.call('SADD', KEYS[4], ARGV[4])
        for _, set in ipairs({KEYS[2], KEYS[4]}) do
            if redis.call('TTL', set) < ttl then redis.call('EXPIRE', set, ttl) end
        end
        return 1
        ",
    )
});

/// Mark `KEYS[1]` used if it is unused: `{0, value}` for a fresh token,
/// `{1, value}` for a reused one (whose family the caller revokes), or nil.
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

/// Revoke the families in `ARGV[4..]` (or, with `ARGV[2]` = a user set key,
/// every family in that set, then the set): delete each one's tokens
/// (`ARGV[1]` + id) and set, and leave a tombstone (`ARGV[3]` + family, for
/// `TOMBSTONE_SECONDS`).
static REVOKE_SCRIPT: std::sync::LazyLock<redis::Script> = std::sync::LazyLock::new(|| {
    redis::Script::new(&format!(
        r"
        local families = {{}}
        for i = 5, #ARGV do table.insert(families, ARGV[i]) end
        if ARGV[2] ~= '' then
            for _, f in ipairs(redis.call('SMEMBERS', ARGV[2])) do table.insert(families, f) end
            redis.call('DEL', ARGV[2])
        end
        for _, family in ipairs(families) do
            local set = ARGV[4] .. family
            for _, id in ipairs(redis.call('SMEMBERS', set)) do
                redis.call('DEL', ARGV[1] .. id)
            end
            redis.call('DEL', set)
            redis.call('SET', ARGV[3] .. family, '1', 'EX', {TOMBSTONE_SECONDS})
        end
        return #families
        "
    ))
});

fn unexpected(e: impl std::error::Error + Send + Sync + 'static) -> RefreshTokenStoreError {
    // Keep the store's own error as the source (a caller can downcast it).
    RefreshTokenStoreError::UnexpectedError(tempered_core::Failure::new(e))
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
    /// Revoke `families`, and with `user_set`, every family it lists.
    async fn revoke(
        &self,
        user_set: Option<&str>,
        families: &[&str],
    ) -> Result<(), RefreshTokenStoreError> {
        let mut invocation = REVOKE_SCRIPT.prepare_invoke();
        invocation
            .arg(TOKEN_PREFIX)
            .arg(user_set.unwrap_or(""))
            .arg(REVOKED_PREFIX)
            .arg(FAMILY_PREFIX);
        for family in families {
            invocation.arg(*family);
        }
        let _: i64 = invocation
            .invoke_async(&mut self.client.clone())
            .await
            .map_err(unexpected)?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl RefreshTokenStore for RedisRefreshTokenStore {
    async fn create(
        &self,
        token: RefreshTokenHash,
        record: RefreshRecord,
    ) -> Result<(), RefreshTokenStoreError> {
        let ttl = record.expires_at.saturating_sub(now()).max(1);
        let value = serde_json::to_string(&Stored {
            email: record.email.as_ref().expose_secret().clone(),
            user_id: record.user_id,
            family: record.family.clone(),
            expires_at: record.expires_at,
        })
        .map_err(unexpected)?;
        let created: i64 = CREATE_SCRIPT
            .key(token_key(&token))
            .key(format!("{FAMILY_PREFIX}{}", record.family))
            .key(format!("{REVOKED_PREFIX}{}", record.family))
            .key(user_key(USER_PREFIX, &record.email))
            .arg(value)
            .arg(ttl)
            .arg(URL_SAFE_NO_PAD.encode(token))
            .arg(&record.family)
            .invoke_async(&mut self.client.clone())
            .await
            .map_err(unexpected)?;
        if created == 0 {
            return Err(RefreshTokenStoreError::NotFound);
        }
        Ok(())
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
        if reused == 1 {
            self.revoke(None, &[&stored.family]).await?;
            return Err(RefreshTokenStoreError::Reused { email });
        }
        if stored.expires_at <= now() {
            return Err(RefreshTokenStoreError::NotFound);
        }
        Ok(RefreshRecord {
            email,
            user_id: stored.user_id,
            family: stored.family,
            expires_at: stored.expires_at,
        })
    }

    async fn revoke_family(&self, family: &str) -> Result<(), RefreshTokenStoreError> {
        self.revoke(None, &[family]).await
    }

    async fn revoke_all_for_user(&self, email: &Email) -> Result<(), RefreshTokenStoreError> {
        self.revoke(Some(&user_key(USER_PREFIX, email)), &[]).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{contract, test_support};
    use redis::AsyncCommands;

    #[tokio::test]
    async fn meets_the_refresh_token_store_contract() {
        let (_redis, connection) = test_support::redis::connection().await;
        contract::refresh_token_store(RedisRefreshTokenStore::new(connection)).await;
    }

    /// A short-lived family must not cut short the index a revoke-all reads.
    #[tokio::test]
    async fn the_user_index_lives_as_long_as_the_longest_family() {
        let (_redis, connection) = test_support::redis::connection().await;
        let store = RedisRefreshTokenStore::new(connection.clone());
        let email = contract::email("a@example.com");
        let record = |family: &str, ttl: u64| RefreshRecord {
            email: email.clone(),
            user_id: tempered_core::UserId::new(),
            family: family.to_string(),
            expires_at: now() + ttl,
        };
        store.create([1; 32], record("long", 3600)).await.unwrap();
        store.create([2; 32], record("short", 5)).await.unwrap();
        let ttl: i64 = connection
            .clone()
            .ttl(user_key(USER_PREFIX, &email))
            .await
            .unwrap();
        assert!(ttl > 3000, "{ttl}");
    }
}
