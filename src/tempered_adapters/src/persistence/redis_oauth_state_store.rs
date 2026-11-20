use std::sync::Arc;

use redis::Commands;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use tempered_core::{OAuthStateStore, OAuthStateStoreError, PendingAuthorization};

const STATE_PREFIX: &str = "oauth_state:";

/// Redis-backed [`OAuthStateStore`]: `oauth_state:{state}` holds the provider
/// and the PKCE verifier, expiring after `ttl_seconds` (ten minutes is
/// plenty for a user to get through the provider's login). Consumed with
/// `GETDEL`, so a state is redeemed at most once across all instances.
#[derive(Clone)]
pub struct RedisOAuthStateStore {
    client: Arc<RwLock<redis::Connection>>,
    ttl_seconds: u64,
}

impl RedisOAuthStateStore {
    pub fn new(client: Arc<RwLock<redis::Connection>>, ttl_seconds: u64) -> Self {
        Self {
            client,
            ttl_seconds,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Stored {
    provider: String,
    code_verifier: String,
}

fn unexpected(e: impl std::fmt::Display) -> OAuthStateStoreError {
    OAuthStateStoreError::UnexpectedError(e.to_string())
}

#[async_trait::async_trait]
impl OAuthStateStore for RedisOAuthStateStore {
    async fn store_state(
        &self,
        state: String,
        pending: PendingAuthorization,
    ) -> Result<(), OAuthStateStoreError> {
        let value = serde_json::to_string(&Stored {
            provider: pending.provider,
            code_verifier: pending.code_verifier.expose_secret().clone(),
        })
        .map_err(unexpected)?;
        self.client
            .write()
            .await
            .set_ex(format!("{STATE_PREFIX}{state}"), value, self.ttl_seconds)
            .map_err(unexpected)
    }

    async fn consume_state(
        &self,
        state: &str,
    ) -> Result<PendingAuthorization, OAuthStateStoreError> {
        let value: Option<String> = self
            .client
            .write()
            .await
            .get_del(format!("{STATE_PREFIX}{state}"))
            .map_err(unexpected)?;
        let stored: Stored =
            serde_json::from_str(&value.ok_or(OAuthStateStoreError::UnknownState)?)
                .map_err(unexpected)?;
        Ok(PendingAuthorization {
            provider: stored.provider,
            code_verifier: Secret::new(stored.code_verifier),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{contract, test_support};

    #[tokio::test]
    async fn meets_the_oauth_state_store_contract() {
        let (_redis, connection) = test_support::redis::connection().await;
        contract::oauth_state_store(RedisOAuthStateStore::new(connection, 600)).await;
    }
}
