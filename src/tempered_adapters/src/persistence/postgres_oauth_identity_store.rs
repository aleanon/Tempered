use sqlx::{PgPool, Row};
use tempered_core::{OAuthIdentityStore, OAuthIdentityStoreError, UserId};

/// PostgreSQL-backed [`OAuthIdentityStore`] (table `oauth_identities`, see
/// the crate's migrations; like [`PostgresUserStore`](super::PostgresUserStore),
/// `new` does not run them).
///
/// A link is only ever inserted or deleted, never updated, so an identity
/// cannot be moved to another account by a racing request. Links reference
/// the account (`users.id`) and go with it when it is deleted.
#[derive(Clone)]
pub struct PostgresOAuthIdentityStore {
    pool: PgPool,
}

impl PostgresOAuthIdentityStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn unexpected(e: impl std::error::Error + Send + Sync + 'static) -> OAuthIdentityStoreError {
    // Keep the store's own error as the source (a caller can downcast it).
    OAuthIdentityStoreError::UnexpectedError(tempered_core::Failure::new(e))
}

#[async_trait::async_trait]
impl OAuthIdentityStore for PostgresOAuthIdentityStore {
    #[tracing::instrument(name = "Link OAuth identity", skip_all)]
    async fn link_identity(
        &self,
        provider: String,
        subject: String,
        user: UserId,
    ) -> Result<(), OAuthIdentityStoreError> {
        let inserted = sqlx::query(
            "INSERT INTO oauth_identities (provider, subject, user_id) VALUES ($1, $2, $3)
             ON CONFLICT (provider, subject) DO NOTHING",
        )
        .bind(&provider)
        .bind(&subject)
        .bind(user.as_uuid())
        .execute(&self.pool)
        .await
        .map_err(unexpected)?
        .rows_affected();
        if inserted == 1 {
            return Ok(());
        }

        // Already linked: fine if to this account, refused otherwise.
        match self.find_user(&provider, &subject).await? {
            Some(existing) if existing == user => Ok(()),
            Some(_) => Err(OAuthIdentityStoreError::AlreadyLinked),
            // Unlinked in between: a deletion won; the caller can retry.
            None => Err(OAuthIdentityStoreError::UnexpectedError(
                "identity was unlinked while being linked".into(),
            )),
        }
    }

    #[tracing::instrument(name = "Find OAuth identity", skip_all)]
    async fn find_user(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<UserId>, OAuthIdentityStoreError> {
        let row = sqlx::query(
            "SELECT user_id FROM oauth_identities WHERE provider = $1 AND subject = $2",
        )
        .bind(provider)
        .bind(subject)
        .fetch_optional(&self.pool)
        .await
        .map_err(unexpected)?;
        Ok(row.map(|r| UserId::from_uuid(r.get(0))))
    }

    #[tracing::instrument(name = "Has OAuth identity", skip_all)]
    async fn has_identity_for_user(&self, user: &UserId) -> Result<bool, OAuthIdentityStoreError> {
        let row = sqlx::query("SELECT EXISTS(SELECT 1 FROM oauth_identities WHERE user_id = $1)")
            .bind(user.as_uuid())
            .fetch_one(&self.pool)
            .await
            .map_err(unexpected)?;
        Ok(row.get(0))
    }

    #[tracing::instrument(name = "Unlink OAuth identities", skip_all)]
    async fn unlink_all_for_user(&self, user: &UserId) -> Result<(), OAuthIdentityStoreError> {
        sqlx::query("DELETE FROM oauth_identities WHERE user_id = $1")
            .bind(user.as_uuid())
            .execute(&self.pool)
            .await
            .map_err(unexpected)?;
        Ok(())
    }

    async fn list_for_user(
        &self,
        user: &UserId,
    ) -> Result<Vec<(String, String)>, OAuthIdentityStoreError> {
        let rows = sqlx::query(
            "SELECT provider, subject FROM oauth_identities WHERE user_id = $1 ORDER BY provider, subject",
        )
        .bind(user.as_uuid())
        .fetch_all(&self.pool)
        .await
        .map_err(unexpected)?;
        Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
    }

    async fn unlink(&self, user: &UserId, provider: &str) -> Result<bool, OAuthIdentityStoreError> {
        let deleted =
            sqlx::query("DELETE FROM oauth_identities WHERE user_id = $1 AND provider = $2")
                .bind(user.as_uuid())
                .bind(provider)
                .execute(&self.pool)
                .await
                .map_err(unexpected)?;
        Ok(deleted.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{contract, test_support};

    #[tokio::test]
    async fn meets_the_oauth_identity_store_contract() {
        let (_postgres, pool) = test_support::postgres::pool().await;
        let users = contract::accounts(
            &crate::persistence::PostgresUserStore::new(pool.clone()),
            ["alice@example.com", "bob@example.com"],
        )
        .await;
        contract::oauth_identity_store(PostgresOAuthIdentityStore::new(pool), users).await;
    }

    /// A link belongs to the account: deleting it deletes them.
    #[tokio::test]
    async fn deleting_the_account_deletes_its_links() {
        use tempered_core::UserStore;
        let (_postgres, pool) = test_support::postgres::pool().await;
        let users = crate::persistence::PostgresUserStore::new(pool.clone());
        let [alice] = contract::accounts(&users, ["alice@example.com"]).await;
        let store = PostgresOAuthIdentityStore::new(pool);
        store
            .link_identity("google".into(), "g-1".into(), alice)
            .await
            .unwrap();
        users
            .delete_user(&contract::email("alice@example.com"))
            .await
            .unwrap();
        assert_eq!(store.find_user("google", "g-1").await.unwrap(), None);
    }
}
