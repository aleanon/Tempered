use redis::{AsyncCommands, aio::ConnectionManager};
use tempered_core::{BannedTokenStore, BannedTokenStoreError};

#[derive(Clone)]
pub struct RedisBannedTokenStore {
    conn: ConnectionManager,
    token_ttl: u64,
}

impl RedisBannedTokenStore {
    pub fn new(conn: ConnectionManager, token_ttl: u64) -> Self {
        Self { conn, token_ttl }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for RedisBannedTokenStore {
    async fn ban_token(&self, token: String) -> Result<(), BannedTokenStoreError> {
        let key = get_key(&token);

        let mut conn = self.conn.clone();
        conn.set_ex(key, true, self.token_ttl)
            .await
            .map_err(|e| BannedTokenStoreError::DatabaseError(e.to_string()))
    }

    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        let key = get_key(token);
        let mut conn = self.conn.clone();
        conn.exists(&key)
            .await
            .map_err(|e| BannedTokenStoreError::DatabaseError(e.to_string()))
    }
}

// We are using a key prefix to prevent collisions and organize data!
const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

fn get_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token)
}
