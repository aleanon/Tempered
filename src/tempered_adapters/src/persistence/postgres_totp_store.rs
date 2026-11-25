use secrecy::{ExposeSecret, Secret};
use sqlx::{PgPool, Row};
use tempered_core::{RecoveryCodeHash, TotpStore, TotpStoreError, UserId};

/// PostgreSQL-backed [`TotpStore`] (tables `totp_secrets` and
/// `totp_recovery_codes`, in `migrations/`; like the other stores it does
/// not run them).
///
/// Secrets are stored as given. If the database is not encrypted at rest,
/// that is where a stolen backup would get them.
#[derive(Clone)]
pub struct PostgresTotpStore {
    pool: PgPool,
}

impl PostgresTotpStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn unexpected(e: impl std::error::Error + Send + Sync + 'static) -> TotpStoreError {
    // Keep the store's own error as the source (a caller can downcast it).
    TotpStoreError::UnexpectedError(tempered_core::Failure::new(e))
}

fn key(user: &UserId) -> uuid::Uuid {
    user.as_uuid()
}

#[async_trait::async_trait]
impl TotpStore for PostgresTotpStore {
    async fn set_pending(
        &self,
        user: &UserId,
        secret: Secret<Vec<u8>>,
    ) -> Result<(), TotpStoreError> {
        sqlx::query(
            "INSERT INTO totp_secrets (user_id, pending) VALUES ($1, $2)
             ON CONFLICT (user_id) DO UPDATE SET pending = EXCLUDED.pending",
        )
        .bind(key(user))
        .bind(secret.expose_secret())
        .execute(&self.pool)
        .await
        .map_err(unexpected)?;
        Ok(())
    }

    async fn pending(&self, user: &UserId) -> Result<Option<Secret<Vec<u8>>>, TotpStoreError> {
        let row = sqlx::query("SELECT pending FROM totp_secrets WHERE user_id = $1")
            .bind(key(user))
            .fetch_optional(&self.pool)
            .await
            .map_err(unexpected)?;
        Ok(row
            .and_then(|r| r.get::<Option<Vec<u8>>, _>(0))
            .map(Secret::new))
    }

    async fn activate(
        &self,
        user: &UserId,
        used_step: u64,
        recovery_codes: Vec<RecoveryCodeHash>,
    ) -> Result<bool, TotpStoreError> {
        let mut tx = self.pool.begin().await.map_err(unexpected)?;
        let moved = sqlx::query(
            "UPDATE totp_secrets SET active = pending, pending = NULL, last_step = $2
             WHERE user_id = $1 AND pending IS NOT NULL",
        )
        .bind(key(user))
        .bind(used_step as i64)
        .execute(&mut *tx)
        .await
        .map_err(unexpected)?;
        if moved.rows_affected() == 0 {
            return Ok(false);
        }
        replace_codes(&mut tx, user, &recovery_codes).await?;
        tx.commit().await.map_err(unexpected)?;
        Ok(true)
    }

    async fn active(&self, user: &UserId) -> Result<Option<Secret<Vec<u8>>>, TotpStoreError> {
        let row = sqlx::query("SELECT active FROM totp_secrets WHERE user_id = $1")
            .bind(key(user))
            .fetch_optional(&self.pool)
            .await
            .map_err(unexpected)?;
        Ok(row
            .and_then(|r| r.get::<Option<Vec<u8>>, _>(0))
            .map(Secret::new))
    }

    async fn use_step(&self, user: &UserId, step: u64) -> Result<bool, TotpStoreError> {
        // One conditional UPDATE: of two requests with the same code, one
        // moves the step and the other finds it moved.
        let updated = sqlx::query(
            "UPDATE totp_secrets SET last_step = $2
             WHERE user_id = $1 AND active IS NOT NULL AND (last_step IS NULL OR last_step < $2)",
        )
        .bind(key(user))
        .bind(step as i64)
        .execute(&self.pool)
        .await
        .map_err(unexpected)?;
        Ok(updated.rows_affected() == 1)
    }

    async fn replace_recovery_codes(
        &self,
        user: &UserId,
        recovery_codes: Vec<RecoveryCodeHash>,
    ) -> Result<(), TotpStoreError> {
        let mut tx = self.pool.begin().await.map_err(unexpected)?;
        replace_codes(&mut tx, user, &recovery_codes).await?;
        tx.commit().await.map_err(unexpected)
    }

    async fn use_recovery_code(
        &self,
        user: &UserId,
        code: &RecoveryCodeHash,
    ) -> Result<bool, TotpStoreError> {
        let deleted =
            sqlx::query("DELETE FROM totp_recovery_codes WHERE user_id = $1 AND code_hash = $2")
                .bind(key(user))
                .bind(&code[..])
                .execute(&self.pool)
                .await
                .map_err(unexpected)?;
        Ok(deleted.rows_affected() == 1)
    }

    async fn delete_all_for_user(&self, user: &UserId) -> Result<(), TotpStoreError> {
        let mut tx = self.pool.begin().await.map_err(unexpected)?;
        for table in ["totp_recovery_codes", "totp_secrets"] {
            sqlx::query(&format!("DELETE FROM {table} WHERE user_id = $1"))
                .bind(key(user))
                .execute(&mut *tx)
                .await
                .map_err(unexpected)?;
        }
        tx.commit().await.map_err(unexpected)
    }
}

async fn replace_codes(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user: &UserId,
    codes: &[RecoveryCodeHash],
) -> Result<(), TotpStoreError> {
    sqlx::query("DELETE FROM totp_recovery_codes WHERE user_id = $1")
        .bind(key(user))
        .execute(&mut **tx)
        .await
        .map_err(unexpected)?;
    for code in codes {
        sqlx::query("INSERT INTO totp_recovery_codes (user_id, code_hash) VALUES ($1, $2)")
            .bind(key(user))
            .bind(&code[..])
            .execute(&mut **tx)
            .await
            .map_err(unexpected)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{contract, test_support};

    #[tokio::test]
    async fn meets_the_totp_store_contract() {
        let (_db, pool) = test_support::postgres::pool().await;
        let users = contract::accounts(
            &crate::persistence::PostgresUserStore::new(pool.clone()),
            ["alice@example.com", "bob@example.com"],
        )
        .await;
        contract::totp_store(PostgresTotpStore::new(pool), users).await;
    }

    /// The data belongs to the account: deleting it deletes them, with no
    /// cleanup call.
    #[tokio::test]
    async fn deleting_the_account_deletes_its_totp_data() {
        use tempered_core::UserStore;
        let (_db, pool) = test_support::postgres::pool().await;
        let users = crate::persistence::PostgresUserStore::new(pool.clone());
        let [alice] = contract::accounts(&users, ["alice@example.com"]).await;
        let store = PostgresTotpStore::new(pool);
        store
            .set_pending(&alice, secrecy::Secret::new(vec![1; 20]))
            .await
            .unwrap();
        assert!(store.activate(&alice, 1, vec![[7; 32]]).await.unwrap());

        users
            .delete_user(&contract::email("alice@example.com"))
            .await
            .unwrap();
        assert!(store.active(&alice).await.unwrap().is_none());
        assert!(!store.use_recovery_code(&alice, &[7; 32]).await.unwrap());
    }
}
