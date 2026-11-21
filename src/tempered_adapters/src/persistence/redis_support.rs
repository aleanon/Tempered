//! Pieces shared by the Redis stores.

use redis::{AsyncCommands, RedisResult, aio::ConnectionManager};
use secrecy::ExposeSecret;
use tempered_core::Email;

const USER_LOCK_PREFIX: &str = "user_lock:";

/// A per-user key: `{prefix}{email}`.
pub(crate) fn user_key(prefix: &str, email: &Email) -> String {
    format!("{}{}", prefix, email.as_ref().expose_secret())
}

/// Take the user's credential lock: `SET NX EX`, atomic, with an expiry.
pub(crate) async fn try_lock_user(
    conn: &mut ConnectionManager,
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
        .query_async(conn)
        .await?;
    Ok(reply.is_some())
}

/// Release the lock if `holder` still holds it: compare-and-delete in one
/// step, so a holder whose lock expired cannot release someone else's.
pub(crate) async fn unlock_user(
    conn: &mut ConnectionManager,
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
        .invoke_async(conn)
        .await?;
    Ok(())
}

pub(crate) async fn is_user_locked(
    conn: &mut ConnectionManager,
    email: &Email,
) -> RedisResult<bool> {
    conn.exists(user_key(USER_LOCK_PREFIX, email)).await
}

/// Delete an index set, every `{member_prefix}{member}` key it names, and
/// `also` (more keys to drop in the same step), atomically on the server.
///
/// Reading the set and deleting in a later `MULTI` leaves a gap: another
/// instance can add a member in between, and deleting the set then leaves
/// that member's key alive and no longer indexed, so a later purge misses
/// it. A script runs as one step, so nothing lands in between.
///
/// The member keys are built inside the script, so they are not declared in
/// `KEYS`. That is fine on a single Redis; on Redis Cluster the stores
/// would need hash tags to keep a user's keys in one slot.
pub(crate) async fn purge_index(
    conn: &mut ConnectionManager,
    index: &str,
    member_prefix: &str,
    also: &[String],
) -> RedisResult<()> {
    let script = redis::Script::new(
        "for _, member in ipairs(redis.call('smembers', KEYS[1])) do \
             redis.call('del', ARGV[1] .. member) \
         end \
         for i = 1, #KEYS do redis.call('del', KEYS[i]) end \
         return 0",
    );
    let mut invocation = script.key(index);
    for key in also {
        invocation.key(key);
    }
    let _: i64 = invocation.arg(member_prefix).invoke_async(conn).await?;
    Ok(())
}
