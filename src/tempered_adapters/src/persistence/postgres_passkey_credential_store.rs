use secrecy::{ExposeSecret, Secret};
use sqlx::PgPool;
use tempered_core::{
    CredentialId, Email, PasskeyCredential, PasskeyCredentialStore, PasskeyStoreError,
};

/// PostgreSQL-backed [`PasskeyCredentialStore`] (table `passkey_credentials`,
/// see the crate's migrations; `new` does not run them).
///
/// The credential id is the primary key, so enrolment is insert-only, and the
/// sign-count update is one conditional `UPDATE`: of two concurrent logins
/// presenting the same counter, one wins.
#[derive(Clone)]
pub struct PostgresPasskeyCredentialStore {
    pool: PgPool,
}

impl PostgresPasskeyCredentialStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn unexpected(e: impl std::fmt::Display) -> PasskeyStoreError {
    PasskeyStoreError::UnexpectedError(e.to_string())
}

fn credential(
    credential_id: String,
    owner: String,
    credential_data: Vec<u8>,
    sign_count: i64,
    name: Option<String>,
) -> Result<PasskeyCredential, PasskeyStoreError> {
    Ok(PasskeyCredential {
        credential_id: CredentialId(credential_id),
        owner: Email::try_from(Secret::new(owner)).map_err(unexpected)?,
        credential_data,
        sign_count: u32::try_from(sign_count).map_err(unexpected)?,
        name,
    })
}

#[async_trait::async_trait]
impl PasskeyCredentialStore for PostgresPasskeyCredentialStore {
    #[tracing::instrument(name = "Add passkey credential", skip_all)]
    async fn add_credential(&self, cred: PasskeyCredential) -> Result<(), PasskeyStoreError> {
        sqlx::query!(
            r#"
                INSERT INTO passkey_credentials (credential_id, owner, credential_data, sign_count, name)
                VALUES ($1, $2, $3, $4, $5)
            "#,
            cred.credential_id.as_str(),
            cred.owner.as_ref().expose_secret(),
            cred.credential_data,
            i64::from(cred.sign_count),
            cred.name
        )
        .execute(&self.pool)
        .await
        .map_err(|e| match e.as_database_error() {
            Some(db) if db.is_unique_violation() => PasskeyStoreError::CredentialAlreadyExists,
            _ => unexpected(e),
        })?;
        Ok(())
    }

    #[tracing::instrument(name = "Get passkey credential", skip_all)]
    async fn get_credential(
        &self,
        id: &CredentialId,
    ) -> Result<PasskeyCredential, PasskeyStoreError> {
        let row = sqlx::query!(
            r#"
                SELECT credential_id, owner, credential_data, sign_count, name
                FROM passkey_credentials WHERE credential_id = $1
            "#,
            id.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(unexpected)?
        .ok_or(PasskeyStoreError::CredentialNotFound)?;
        credential(
            row.credential_id,
            row.owner,
            row.credential_data,
            row.sign_count,
            row.name,
        )
    }

    #[tracing::instrument(name = "List passkey credentials", skip_all)]
    async fn list_for_user(
        &self,
        owner: &Email,
    ) -> Result<Vec<PasskeyCredential>, PasskeyStoreError> {
        sqlx::query!(
            r#"
                SELECT credential_id, owner, credential_data, sign_count, name
                FROM passkey_credentials WHERE owner = $1
            "#,
            owner.as_ref().expose_secret()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(unexpected)?
        .into_iter()
        .map(|row| {
            credential(
                row.credential_id,
                row.owner,
                row.credential_data,
                row.sign_count,
                row.name,
            )
        })
        .collect()
    }

    async fn delete_credential(
        &self,
        owner: &Email,
        id: &CredentialId,
    ) -> Result<bool, PasskeyStoreError> {
        let deleted =
            sqlx::query("DELETE FROM passkey_credentials WHERE credential_id = $1 AND owner = $2")
                .bind(id.as_str())
                .bind(owner.as_ref().expose_secret())
                .execute(&self.pool)
                .await
                .map_err(unexpected)?;
        Ok(deleted.rows_affected() == 1)
    }

    async fn rename_credential(
        &self,
        owner: &Email,
        id: &CredentialId,
        name: Option<String>,
    ) -> Result<bool, PasskeyStoreError> {
        let renamed = sqlx::query(
            "UPDATE passkey_credentials SET name = $3 WHERE credential_id = $1 AND owner = $2",
        )
        .bind(id.as_str())
        .bind(owner.as_ref().expose_secret())
        .bind(name)
        .execute(&self.pool)
        .await
        .map_err(unexpected)?;
        Ok(renamed.rows_affected() == 1)
    }

    #[tracing::instrument(name = "Update passkey after authentication", skip_all)]
    async fn update_after_authentication(
        &self,
        id: &CredentialId,
        new_sign_count: u32,
        credential_data: Option<Vec<u8>>,
    ) -> Result<(), PasskeyStoreError> {
        let new_sign_count = i64::from(new_sign_count);
        // Check and write in one statement (the port's contract).
        let updated = sqlx::query!(
            r#"
                UPDATE passkey_credentials
                SET sign_count = $2,
                    credential_data = COALESCE($3, credential_data)
                WHERE credential_id = $1
                  AND (sign_count < $2 OR ($2 = 0 AND sign_count = 0))
            "#,
            id.as_str(),
            new_sign_count,
            credential_data
        )
        .execute(&self.pool)
        .await
        .map_err(unexpected)?
        .rows_affected();
        if updated == 1 {
            return Ok(());
        }
        // Nothing changed: either there is no such credential, or the counter
        // did not advance.
        self.get_credential(id).await?;
        Err(PasskeyStoreError::SignCountNotAdvanced)
    }

    #[tracing::instrument(name = "Delete passkey credentials", skip_all)]
    async fn delete_all_for_user(&self, owner: &Email) -> Result<(), PasskeyStoreError> {
        sqlx::query!(
            r#"DELETE FROM passkey_credentials WHERE owner = $1"#,
            owner.as_ref().expose_secret()
        )
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
    async fn meets_the_passkey_credential_store_contract() {
        let (_postgres, pool) = test_support::postgres::pool().await;
        contract::passkey_credential_store(PostgresPasskeyCredentialStore::new(pool)).await;
    }

    #[tokio::test]
    async fn of_concurrent_logins_with_the_same_counter_exactly_one_wins() {
        let (_postgres, pool) = test_support::postgres::pool().await;
        let store = PostgresPasskeyCredentialStore::new(pool);
        store
            .add_credential(PasskeyCredential {
                credential_id: CredentialId("c".to_string()),
                credential_data: vec![1],
                sign_count: 1,
                owner: contract::email("a@example.com"),
                name: None,
            })
            .await
            .unwrap();

        // A replayed assertion presented many times at once.
        let attempts = (0..16).map(|_| {
            let store = store.clone();
            tokio::spawn(async move {
                store
                    .update_after_authentication(&CredentialId("c".to_string()), 2, None)
                    .await
            })
        });
        let results = futures_join_all(attempts).await;
        let won = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(won, 1);
        assert!(
            results
                .iter()
                .all(|r| r.is_ok() || matches!(r, Err(PasskeyStoreError::SignCountNotAdvanced)))
        );
    }

    async fn futures_join_all<T>(
        handles: impl Iterator<Item = tokio::task::JoinHandle<T>>,
    ) -> Vec<T> {
        let mut out = Vec::new();
        for handle in handles.collect::<Vec<_>>() {
            out.push(handle.await.unwrap());
        }
        out
    }
}
