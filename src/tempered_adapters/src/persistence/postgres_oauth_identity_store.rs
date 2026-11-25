use secrecy::{ExposeSecret, Secret};
use sqlx::PgPool;
use tempered_core::{Email, OAuthIdentityStore, OAuthIdentityStoreError};

/// PostgreSQL-backed [`OAuthIdentityStore`] (table `oauth_identities`, see
/// the crate's migrations; like [`PostgresUserStore`](super::PostgresUserStore),
/// `new` does not run them).
///
/// A link is only ever inserted or deleted, never updated, so an identity
/// cannot be moved to another account by a racing request.
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

fn parse_email(value: String) -> Result<Email, OAuthIdentityStoreError> {
    Email::try_from(Secret::new(value)).map_err(unexpected)
}

#[async_trait::async_trait]
impl OAuthIdentityStore for PostgresOAuthIdentityStore {
    #[tracing::instrument(name = "Link OAuth identity", skip_all)]
    async fn link_identity(
        &self,
        provider: String,
        subject: String,
        email: Email,
    ) -> Result<(), OAuthIdentityStoreError> {
        let inserted = sqlx::query!(
            r#"
                INSERT INTO oauth_identities (provider, subject, email)
                VALUES ($1, $2, $3)
                ON CONFLICT (provider, subject) DO NOTHING
            "#,
            provider,
            subject,
            email.as_ref().expose_secret()
        )
        .execute(&self.pool)
        .await
        .map_err(unexpected)?
        .rows_affected();
        if inserted == 1 {
            return Ok(());
        }

        // Already linked: fine if to this account, refused otherwise.
        match self.find_email(&provider, &subject).await? {
            Some(existing) if existing == email => Ok(()),
            Some(_) => Err(OAuthIdentityStoreError::AlreadyLinked),
            // Unlinked in between: a deletion won; the caller can retry.
            None => Err(OAuthIdentityStoreError::UnexpectedError(
                "identity was unlinked while being linked".into(),
            )),
        }
    }

    #[tracing::instrument(name = "Find OAuth identity", skip_all)]
    async fn find_email(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<Email>, OAuthIdentityStoreError> {
        let row = sqlx::query!(
            r#"SELECT email FROM oauth_identities WHERE provider = $1 AND subject = $2"#,
            provider,
            subject
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(unexpected)?;
        row.map(|r| parse_email(r.email)).transpose()
    }

    #[tracing::instrument(name = "Has OAuth identity", skip_all)]
    async fn has_identity_for_email(&self, email: &Email) -> Result<bool, OAuthIdentityStoreError> {
        let row = sqlx::query!(
            r#"SELECT EXISTS(SELECT 1 FROM oauth_identities WHERE email = $1) AS "linked!""#,
            email.as_ref().expose_secret()
        )
        .fetch_one(&self.pool)
        .await
        .map_err(unexpected)?;
        Ok(row.linked)
    }

    #[tracing::instrument(name = "Unlink OAuth identities", skip_all)]
    async fn unlink_all_for_email(&self, email: &Email) -> Result<(), OAuthIdentityStoreError> {
        sqlx::query!(
            r#"DELETE FROM oauth_identities WHERE email = $1"#,
            email.as_ref().expose_secret()
        )
        .execute(&self.pool)
        .await
        .map_err(unexpected)?;
        Ok(())
    }

    async fn list_for_user(
        &self,
        email: &Email,
    ) -> Result<Vec<(String, String)>, OAuthIdentityStoreError> {
        use sqlx::Row;
        let rows = sqlx::query(
            "SELECT provider, subject FROM oauth_identities WHERE email = $1 ORDER BY provider, subject",
        )
        .bind(email.as_ref().expose_secret())
        .fetch_all(&self.pool)
        .await
        .map_err(unexpected)?;
        Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
    }

    async fn unlink(&self, email: &Email, provider: &str) -> Result<bool, OAuthIdentityStoreError> {
        let deleted =
            sqlx::query("DELETE FROM oauth_identities WHERE email = $1 AND provider = $2")
                .bind(email.as_ref().expose_secret())
                .bind(provider)
                .execute(&self.pool)
                .await
                .map_err(unexpected)?;
        Ok(deleted.rows_affected() > 0)
    }

    async fn reassign(&self, old: &Email, new: &Email) -> Result<(), OAuthIdentityStoreError> {
        sqlx::query("UPDATE oauth_identities SET email = $2 WHERE email = $1")
            .bind(old.as_ref().expose_secret())
            .bind(new.as_ref().expose_secret())
            .execute(&self.pool)
            .await
            .map_err(unexpected)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{contract, test_support};

    #[tokio::test]
    async fn meets_the_oauth_identity_store_contract() {
        let (_postgres, pool) = test_support::postgres::pool().await;
        contract::oauth_identity_store(PostgresOAuthIdentityStore::new(pool)).await;
    }
}
