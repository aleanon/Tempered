use secrecy::{ExposeSecret, Secret};
use sqlx::{PgPool, Row};
use tempered_core::{Email, RecoveryCodeHash, TotpStore, TotpStoreError};

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

fn key(email: &Email) -> &str {
    email.as_ref().expose_secret()
}

#[async_trait::async_trait]
impl TotpStore for PostgresTotpStore {
    async fn set_pending(
        &self,
        email: &Email,
        secret: Secret<Vec<u8>>,
    ) -> Result<(), TotpStoreError> {
        sqlx::query(
            "INSERT INTO totp_secrets (email, pending) VALUES ($1, $2)
             ON CONFLICT (email) DO UPDATE SET pending = EXCLUDED.pending",
        )
        .bind(key(email))
        .bind(secret.expose_secret())
        .execute(&self.pool)
        .await
        .map_err(unexpected)?;
        Ok(())
    }

    async fn pending(&self, email: &Email) -> Result<Option<Secret<Vec<u8>>>, TotpStoreError> {
        let row = sqlx::query("SELECT pending FROM totp_secrets WHERE email = $1")
            .bind(key(email))
            .fetch_optional(&self.pool)
            .await
            .map_err(unexpected)?;
        Ok(row
            .and_then(|r| r.get::<Option<Vec<u8>>, _>(0))
            .map(Secret::new))
    }

    async fn activate(
        &self,
        email: &Email,
        used_step: u64,
        recovery_codes: Vec<RecoveryCodeHash>,
    ) -> Result<bool, TotpStoreError> {
        let mut tx = self.pool.begin().await.map_err(unexpected)?;
        let moved = sqlx::query(
            "UPDATE totp_secrets SET active = pending, pending = NULL, last_step = $2
             WHERE email = $1 AND pending IS NOT NULL",
        )
        .bind(key(email))
        .bind(used_step as i64)
        .execute(&mut *tx)
        .await
        .map_err(unexpected)?;
        if moved.rows_affected() == 0 {
            return Ok(false);
        }
        replace_codes(&mut tx, email, &recovery_codes).await?;
        tx.commit().await.map_err(unexpected)?;
        Ok(true)
    }

    async fn active(&self, email: &Email) -> Result<Option<Secret<Vec<u8>>>, TotpStoreError> {
        let row = sqlx::query("SELECT active FROM totp_secrets WHERE email = $1")
            .bind(key(email))
            .fetch_optional(&self.pool)
            .await
            .map_err(unexpected)?;
        Ok(row
            .and_then(|r| r.get::<Option<Vec<u8>>, _>(0))
            .map(Secret::new))
    }

    async fn use_step(&self, email: &Email, step: u64) -> Result<bool, TotpStoreError> {
        // One conditional UPDATE: of two requests with the same code, one
        // moves the step and the other finds it moved.
        let updated = sqlx::query(
            "UPDATE totp_secrets SET last_step = $2
             WHERE email = $1 AND active IS NOT NULL AND (last_step IS NULL OR last_step < $2)",
        )
        .bind(key(email))
        .bind(step as i64)
        .execute(&self.pool)
        .await
        .map_err(unexpected)?;
        Ok(updated.rows_affected() == 1)
    }

    async fn replace_recovery_codes(
        &self,
        email: &Email,
        recovery_codes: Vec<RecoveryCodeHash>,
    ) -> Result<(), TotpStoreError> {
        let mut tx = self.pool.begin().await.map_err(unexpected)?;
        replace_codes(&mut tx, email, &recovery_codes).await?;
        tx.commit().await.map_err(unexpected)
    }

    async fn use_recovery_code(
        &self,
        email: &Email,
        code: &RecoveryCodeHash,
    ) -> Result<bool, TotpStoreError> {
        let deleted =
            sqlx::query("DELETE FROM totp_recovery_codes WHERE email = $1 AND code_hash = $2")
                .bind(key(email))
                .bind(&code[..])
                .execute(&self.pool)
                .await
                .map_err(unexpected)?;
        Ok(deleted.rows_affected() == 1)
    }

    async fn delete_all_for_user(&self, email: &Email) -> Result<(), TotpStoreError> {
        let mut tx = self.pool.begin().await.map_err(unexpected)?;
        for table in ["totp_recovery_codes", "totp_secrets"] {
            sqlx::query(&format!("DELETE FROM {table} WHERE email = $1"))
                .bind(key(email))
                .execute(&mut *tx)
                .await
                .map_err(unexpected)?;
        }
        tx.commit().await.map_err(unexpected)
    }

    async fn reassign(&self, old: &Email, new: &Email) -> Result<(), TotpStoreError> {
        let mut tx = self.pool.begin().await.map_err(unexpected)?;
        for table in ["totp_secrets", "totp_recovery_codes"] {
            sqlx::query(&format!("UPDATE {table} SET email = $2 WHERE email = $1"))
                .bind(key(old))
                .bind(key(new))
                .execute(&mut *tx)
                .await
                .map_err(unexpected)?;
        }
        tx.commit().await.map_err(unexpected)
    }
}

async fn replace_codes(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    email: &Email,
    codes: &[RecoveryCodeHash],
) -> Result<(), TotpStoreError> {
    sqlx::query("DELETE FROM totp_recovery_codes WHERE email = $1")
        .bind(key(email))
        .execute(&mut **tx)
        .await
        .map_err(unexpected)?;
    for code in codes {
        sqlx::query("INSERT INTO totp_recovery_codes (email, code_hash) VALUES ($1, $2)")
            .bind(key(email))
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
        contract::totp_store(PostgresTotpStore::new(pool)).await;
    }
}
