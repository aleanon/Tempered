// Production persistence adapters
pub mod postgres_user_store;
pub mod redis_banned_token_store;
pub mod redis_two_fa_code_store;

// Test-only persistence adapters
pub mod hashmap_two_fa_code_store;
pub mod hashmap_user_store;
pub mod hashset_banned_token_store;

// Re-exports
pub use postgres_user_store::PostgresUserStore;
pub use redis_banned_token_store::RedisBannedTokenStore;
pub use redis_two_fa_code_store::RedisTwoFaCodeStore;

pub use hashmap_two_fa_code_store::HashMapTwoFaCodeStore;
pub use hashmap_user_store::HashMapUserStore;
pub use hashset_banned_token_store::HashSetBannedTokenStore;
