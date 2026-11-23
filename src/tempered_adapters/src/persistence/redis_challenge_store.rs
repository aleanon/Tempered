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
    /// Absent in ceremonies stored by an earlier version; those read as not
    /// found (a ceremony lasts minutes, so the user just starts again).
    #[serde(default)]
    kind: Option<StoredKind>,
    user: Option<String>,
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

fn unexpected(e: impl std::fmt::Display) -> ChallengeStoreError {
    ChallengeStoreError::UnexpectedError(e.to_string())
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
            kind: Some(ceremony.kind.into()),
            user: ceremony
                .user
                .as_ref()
                .map(|e| e.as_ref().expose_secret().clone()),
            state: STANDARD.encode(&ceremony.state.0),
        })
        .map_err(unexpected)?;

        let mut pipe = redis::pipe();
        pipe.atomic()
            .set_ex(ceremony_key(id.as_str()), value, self.ttl_seconds)
            .ignore();
        if let Some(user) = &ceremony.user {
            let set = user_key(USER_CEREMONIES_PREFIX, user);
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

        let user = stored
            .user
            .map(|u| Email::try_from(Secret::new(u)).map_err(unexpected))
            .transpose()?;
        if let Some(user) = &user {
            let _: i64 = client
                .srem(user_key(USER_CEREMONIES_PREFIX, user), id.as_str())
                .await
                .map_err(unexpected)?;
        }
        Ok(PendingCeremony {
            kind: stored
                .kind
                .ok_or(ChallengeStoreError::ChallengeNotFound)?
                .into(),
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

    /// A ceremony stored before ceremonies had a kind cannot be told apart,
    /// so it is not offered to either `finish_*`.
    #[tokio::test]
    async fn a_ceremony_stored_without_its_kind_is_not_found() {
        let (_redis, mut connection) = test_support::redis::connection().await;
        let store = RedisChallengeStore::new(connection.clone(), 300);
        let _: () = connection
            .set(ceremony_key("old"), r#"{"user":null,"state":"AA=="}"#)
            .await
            .unwrap();
        assert!(matches!(
            store.consume_ceremony(&CeremonyId("old".to_string())).await,
            Err(ChallengeStoreError::ChallengeNotFound)
        ));
    }
}
