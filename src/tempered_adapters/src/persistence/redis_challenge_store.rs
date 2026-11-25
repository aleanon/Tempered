use base64::{Engine, engine::general_purpose::STANDARD};
use redis::{AsyncCommands, aio::ConnectionManager};
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};

use tempered_core::{
    CeremonyId, CeremonyKind, CeremonyState, ChallengeStore, ChallengeStoreError, Email,
    PendingCeremony,
};

use super::redis_support::{purge_index, user_key};

const CEREMONY_PREFIX: &str = "passkey_ceremony:";
const USER_CEREMONIES_PREFIX: &str = "passkey_ceremonies:";

/// Redis-backed [`ChallengeStore`] for in-flight WebAuthn ceremonies.
///
/// `passkey_ceremony:{id}` holds the user and the verifier's opaque state,
/// expiring after `ttl_seconds` (a few minutes; browsers time a ceremony out
/// after about five). Consumed with `GETDEL`. A per-user set lists the
/// ceremonies started for a user, so they can be dropped when the user's
/// credentials are removed.
#[derive(Clone)]
pub struct RedisChallengeStore {
    client: ConnectionManager,
    ttl_seconds: u64,
}

impl RedisChallengeStore {
    pub fn new(client: ConnectionManager, ttl_seconds: u64) -> Self {
        Self {
            client,
            ttl_seconds,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Stored {
    kind: StoredKind,
    /// The account's address (what ceremonies are filed by).
    user: Option<String>,
    /// The account's id.
    user_id: Option<tempered_core::UserId>,
    /// Base64 of the opaque state bytes.
    state: String,
}

#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum StoredKind {
    Registration,
    Authentication,
}

impl From<CeremonyKind> for StoredKind {
    fn from(kind: CeremonyKind) -> Self {
        match kind {
            CeremonyKind::Registration => StoredKind::Registration,
            CeremonyKind::Authentication => StoredKind::Authentication,
        }
    }
}

impl From<StoredKind> for CeremonyKind {
    fn from(kind: StoredKind) -> Self {
        match kind {
            StoredKind::Registration => CeremonyKind::Registration,
            StoredKind::Authentication => CeremonyKind::Authentication,
        }
    }
}

fn unexpected(e: impl std::error::Error + Send + Sync + 'static) -> ChallengeStoreError {
    // Keep the store's own error as the source (a caller can downcast it).
    ChallengeStoreError::UnexpectedError(tempered_core::Failure::new(e))
}

fn ceremony_key(id: &str) -> String {
    format!("{CEREMONY_PREFIX}{id}")
}

#[async_trait::async_trait]
impl ChallengeStore for RedisChallengeStore {
    async fn store_ceremony(
        &self,
        id: CeremonyId,
        ceremony: PendingCeremony,
    ) -> Result<(), ChallengeStoreError> {
        let value = serde_json::to_string(&Stored {
            kind: ceremony.kind.into(),
            user: ceremony
                .user
                .as_ref()
                .map(|u| u.email.as_ref().expose_secret().clone()),
            user_id: ceremony.user.as_ref().map(|u| u.id),
            state: STANDARD.encode(&ceremony.state.0),
        })
        .map_err(unexpected)?;

        let mut pipe = redis::pipe();
        pipe.atomic()
            .set_ex(ceremony_key(id.as_str()), value, self.ttl_seconds)
            .ignore();
        if let Some(user) = &ceremony.user {
            let set = user_key(USER_CEREMONIES_PREFIX, &user.email);
            pipe.sadd(&set, id.as_str())
                .ignore()
                .expire(&set, self.ttl_seconds as i64)
                .ignore();
        }
        pipe.query_async::<()>(&mut self.client.clone())
            .await
            .map_err(unexpected)
    }

    async fn consume_ceremony(
        &self,
        id: &CeremonyId,
    ) -> Result<PendingCeremony, ChallengeStoreError> {
        let mut client = self.client.clone();
        let value: Option<String> = client
            .get_del(ceremony_key(id.as_str()))
            .await
            .map_err(unexpected)?;
        let stored: Stored =
            serde_json::from_str(&value.ok_or(ChallengeStoreError::ChallengeNotFound)?)
                .map_err(unexpected)?;

        let user = match (stored.user, stored.user_id) {
            (Some(email), Some(id)) => Some(tempered_core::Subject {
                id,
                email: Email::try_from(Secret::new(email)).map_err(unexpected)?,
            }),
            (None, None) => None,
            _ => {
                return Err(ChallengeStoreError::UnexpectedError(
                    "a ceremony with half an owner".into(),
                ));
            }
        };
        if let Some(user) = &user {
            let _: i64 = client
                .srem(user_key(USER_CEREMONIES_PREFIX, &user.email), id.as_str())
                .await
                .map_err(unexpected)?;
        }
        Ok(PendingCeremony {
            kind: stored.kind.into(),
            user,
            state: CeremonyState(STANDARD.decode(stored.state).map_err(unexpected)?),
        })
    }

    async fn delete_all_for_user(&self, user: &Email) -> Result<(), ChallengeStoreError> {
        purge_index(
            &mut self.client.clone(),
            &user_key(USER_CEREMONIES_PREFIX, user),
            CEREMONY_PREFIX,
            &[],
        )
        .await
        .map_err(unexpected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{contract, test_support};

    #[tokio::test]
    async fn meets_the_challenge_store_contract() {
        let (_redis, connection) = test_support::redis::connection().await;
        contract::challenge_store(RedisChallengeStore::new(connection, 300)).await;
    }
}
