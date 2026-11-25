use redis::{AsyncCommands, aio::ConnectionManager};
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};

use tempered_core::{OAuthStateStore, OAuthStateStoreError, PendingAuthorization};

const STATE_PREFIX: &str = "oauth_state:";

/// Redis-backed [`OAuthStateStore`]: `oauth_state:{state}` holds the provider
/// and the PKCE verifier, expiring after `ttl_seconds` (ten minutes is
/// plenty for a user to get through the provider's login). Consumed with
/// `GETDEL`, so a state is redeemed at most once across all instances.
#[derive(Clone)]
pub struct RedisOAuthStateStore {
    client: ConnectionManager,
    ttl_seconds: u64,
}

impl RedisOAuthStateStore {
    pub fn new(client: ConnectionManager, ttl_seconds: u64) -> Self {
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
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    link_to: Option<String>,
}

fn unexpected(e: impl std::error::Error + Send + Sync + 'static) -> OAuthStateStoreError {
    // Keep the store's own error as the source (a caller can downcast it).
    OAuthStateStoreError::UnexpectedError(tempered_core::Failure::new(e))
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
            nonce: pending.nonce.map(|n| n.expose_secret().clone()),
            link_to: pending.link_to.map(|e| e.as_ref().expose_secret().clone()),
        })
        .map_err(unexpected)?;
        self.client
            .clone()
            .set_ex(format!("{STATE_PREFIX}{state}"), value, self.ttl_seconds)
            .await
            .map_err(unexpected)
    }

    async fn consume_state(
        &self,
        state: &str,
    ) -> Result<PendingAuthorization, OAuthStateStoreError> {
        let value: Option<String> = self
            .client
            .clone()
            .get_del(format!("{STATE_PREFIX}{state}"))
            .await
            .map_err(unexpected)?;
        let stored: Stored =
            serde_json::from_str(&value.ok_or(OAuthStateStoreError::UnknownState)?)
                .map_err(unexpected)?;
        Ok(PendingAuthorization {
            provider: stored.provider,
            code_verifier: Secret::new(stored.code_verifier),
            nonce: stored.nonce.map(Secret::new),
            link_to: stored
                .link_to
                .map(|e| tempered_core::Email::try_from(Secret::new(e)))
                .transpose()
                .map_err(unexpected)?,
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
