// Production persistence adapters (feature-gated)
pub mod password_hasher;
#[cfg(feature = "postgres")]
pub mod postgres_api_key_store;
#[cfg(feature = "postgres")]
pub mod postgres_oauth_identity_store;
#[cfg(feature = "postgres")]
pub mod postgres_passkey_credential_store;
#[cfg(feature = "postgres")]
pub mod postgres_user_store;
#[cfg(feature = "redis")]
pub mod redis_banned_token_store;
#[cfg(feature = "redis")]
pub mod redis_challenge_store;
#[cfg(feature = "redis")]
pub mod redis_email_verification_token_store;
#[cfg(feature = "redis")]
pub mod redis_oauth_state_store;
#[cfg(feature = "redis")]
pub mod redis_password_reset_token_store;
#[cfg(feature = "redis")]
pub mod redis_session_store;
#[cfg(feature = "redis")]
mod redis_support;
#[cfg(feature = "redis")]
pub mod redis_token_epoch_store;
#[cfg(feature = "redis")]
pub mod redis_two_fa_code_store;

// Test-only persistence adapters
pub mod hashmap_api_key_store;
pub mod hashmap_challenge_store;
pub mod hashmap_email_verification_token_store;
pub mod hashmap_oauth_identity_store;
pub mod hashmap_oauth_state_store;
pub mod hashmap_passkey_credential_store;
pub mod hashmap_password_reset_token_store;
pub mod hashmap_session_store;
pub mod hashmap_token_epoch_store;
pub mod hashmap_two_fa_code_store;
pub mod hashmap_user_store;
pub mod hashset_banned_token_store;
mod user_locks;

#[cfg(test)]
pub(crate) mod contract;
#[cfg(test)]
pub(crate) mod test_support;

// Re-exports
pub use password_hasher::{Argon2Hasher, Argon2Params, PasswordVerdict};
#[cfg(feature = "postgres")]
pub use postgres_api_key_store::PostgresApiKeyStore;
#[cfg(feature = "postgres")]
pub use postgres_oauth_identity_store::PostgresOAuthIdentityStore;
#[cfg(feature = "postgres")]
pub use postgres_passkey_credential_store::PostgresPasskeyCredentialStore;
#[cfg(feature = "postgres")]
pub use postgres_user_store::PostgresUserStore;
#[cfg(feature = "redis")]
pub use redis_banned_token_store::RedisBannedTokenStore;
#[cfg(feature = "redis")]
pub use redis_challenge_store::RedisChallengeStore;
#[cfg(feature = "redis")]
pub use redis_email_verification_token_store::RedisEmailVerificationTokenStore;
#[cfg(feature = "redis")]
pub use redis_oauth_state_store::RedisOAuthStateStore;
#[cfg(feature = "redis")]
pub use redis_password_reset_token_store::RedisPasswordResetTokenStore;
#[cfg(feature = "redis")]
pub use redis_session_store::RedisSessionStore;
#[cfg(feature = "redis")]
pub use redis_token_epoch_store::RedisTokenEpochStore;
#[cfg(feature = "redis")]
pub use redis_two_fa_code_store::RedisTwoFaCodeStore;

pub use hashmap_api_key_store::HashMapApiKeyStore;
pub use hashmap_challenge_store::HashMapChallengeStore;
pub use hashmap_email_verification_token_store::HashMapEmailVerificationTokenStore;
pub use hashmap_oauth_identity_store::HashMapOAuthIdentityStore;
pub use hashmap_oauth_state_store::HashMapOAuthStateStore;
pub use hashmap_passkey_credential_store::HashMapPasskeyCredentialStore;
pub use hashmap_password_reset_token_store::HashMapPasswordResetTokenStore;
pub use hashmap_session_store::HashMapSessionStore;
pub use hashmap_token_epoch_store::HashMapTokenEpochStore;
pub use hashmap_two_fa_code_store::HashMapTwoFaCodeStore;
pub use hashmap_user_store::HashMapUserStore;
pub use hashset_banned_token_store::HashSetBannedTokenStore;
