//! Pieces shared by the Redis stores.

use redis::{Commands, RedisResult};
use secrecy::ExposeSecret;
use tempered_core::Email;

const USER_LOCK_PREFIX: &str = "user_lock:";

/// A per-user key: `{prefix}{email}`.
pub(crate) fn user_key(prefix: &str, email: &Email) -> String {
    format!("{}{}", prefix, email.as_ref().expose_secret())
}

/// Take the user's credential lock: `SET NX EX`, atomic, with an expiry.
pub(crate) fn try_lock_user(
    conn: &mut redis::Connection,
    email: &Email,
    holder: &str,
    ttl_seconds: u64,
) -> RedisResult<bool> {
    // Replies OK, or nil if the lock is held.
    let reply: Option<String> = redis::cmd("SET")
        .arg(user_key(USER_LOCK_PREFIX, email))
        .arg(holder)
        .arg("NX")
        .arg("EX")
        .arg(ttl_seconds)
        .query(conn)?;
    Ok(reply.is_some())
}

/// Release the lock if `holder` still holds it: compare-and-delete in one
/// step, so a holder whose lock expired cannot release someone else's.
pub(crate) fn unlock_user(
    conn: &mut redis::Connection,
    email: &Email,
    holder: &str,
) -> RedisResult<()> {
    let script = redis::Script::new(
        "if redis.call('get', KEYS[1]) == ARGV[1] then \
             return redis.call('del', KEYS[1]) \
         else return 0 end",
    );
    let _: i64 = script
        .key(user_key(USER_LOCK_PREFIX, email))
        .arg(holder)
        .invoke(conn)?;
    Ok(())
}

pub(crate) fn is_user_locked(conn: &mut redis::Connection, email: &Email) -> RedisResult<bool> {
    conn.exists(user_key(USER_LOCK_PREFIX, email))
}
