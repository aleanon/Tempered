use secrecy::{ExposeSecret, Secret};
use sqlx::PgPool;
use tempered_core::{ApiKeyId, ApiKeyMetadata, ApiKeyRecord, ApiKeyStore, ApiKeyStoreError, Email};

/// PostgreSQL-backed [`ApiKeyStore`] (table `api_keys`, see the crate's
/// migrations; `new` does not run them). Holds the SHA-256 of each key's
/// secret half, never the key.
#[derive(Clone)]
pub struct PostgresApiKeyStore {
    pool: PgPool,
}

impl PostgresApiKeyStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn unexpected(e: impl std::error::Error + Send + Sync + 'static) -> ApiKeyStoreError {
    // Keep the store's own error as the source (a caller can downcast it).
    ApiKeyStoreError::UnexpectedError(tempered_core::Failure::new(e))
}

fn parse_id(value: &str) -> Result<ApiKeyId, ApiKeyStoreError> {
    ApiKeyId::parse(value).ok_or_else(|| {
        ApiKeyStoreError::UnexpectedError(format!("malformed key id {value:?}").into())
    })
}

#[async_trait::async_trait]
impl ApiKeyStore for PostgresApiKeyStore {
    #[tracing::instrument(name = "Create API key", skip_all)]
    async fn create_key(&self, record: ApiKeyRecord) -> Result<(), ApiKeyStoreError> {
        sqlx::query!(
            r#"
                INSERT INTO api_keys (id, prefix, secret_hash, owner, scopes, created_at, expires_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            record.id.to_string(),
            record.prefix,
            record.secret_hash,
            record.owner.as_ref().expose_secret(),
            &record.scopes,
            record.created_at as i64,
            record.expires_at.map(|t| t as i64)
        )
        .execute(&self.pool)
        .await
        .map_err(|e| match e.as_database_error() {
            // The only unique columns are the random id and prefix; a clash
            // is a prefix collision (or an id one, handled the same way).
            Some(db) if db.is_unique_violation() => ApiKeyStoreError::PrefixTaken,
            _ => unexpected(e),
        })?;
        Ok(())
    }

    #[tracing::instrument(name = "Find API key", skip_all)]
    async fn find_by_prefix(&self, prefix: &str) -> Result<ApiKeyRecord, ApiKeyStoreError> {
        let row = sqlx::query!(
            r#"SELECT id, prefix, secret_hash, owner, scopes, created_at, expires_at, last_used_at
               FROM api_keys WHERE prefix = $1"#,
            prefix
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(unexpected)?
        .ok_or(ApiKeyStoreError::NotFound)?;
        Ok(ApiKeyRecord {
            id: parse_id(&row.id)?,
            prefix: row.prefix,
            secret_hash: row.secret_hash,
            owner: Email::try_from(Secret::new(row.owner)).map_err(unexpected)?,
            scopes: row.scopes,
            created_at: row.created_at as u64,
            expires_at: row.expires_at.map(|t| t as u64),
            last_used_at: row.last_used_at.map(|t| t as u64),
        })
    }

    #[tracing::instrument(name = "Revoke API key", skip_all)]
    async fn revoke_key(&self, owner: &Email, id: &ApiKeyId) -> Result<(), ApiKeyStoreError> {
        let deleted = sqlx::query!(
            r#"DELETE FROM api_keys WHERE id = $1 AND owner = $2"#,
            id.to_string(),
            owner.as_ref().expose_secret()
        )
        .execute(&self.pool)
        .await
        .map_err(unexpected)?
        .rows_affected();
        if deleted == 0 {
            return Err(ApiKeyStoreError::NotFound);
        }
        Ok(())
    }

    #[tracing::instrument(name = "List API keys", skip_all)]
    async fn list_for_user(&self, owner: &Email) -> Result<Vec<ApiKeyMetadata>, ApiKeyStoreError> {
        sqlx::query!(
            r#"SELECT id, prefix, scopes, created_at, expires_at, last_used_at
               FROM api_keys WHERE owner = $1 ORDER BY created_at"#,
            owner.as_ref().expose_secret()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(unexpected)?
        .into_iter()
        .map(|row| {
            Ok(ApiKeyMetadata {
                id: parse_id(&row.id)?,
                prefix: row.prefix,
                scopes: row.scopes,
                created_at: row.created_at as u64,
                expires_at: row.expires_at.map(|t| t as u64),
                last_used_at: row.last_used_at.map(|t| t as u64),
            })
        })
        .collect()
    }

    async fn record_use(&self, id: &ApiKeyId, at: u64) -> Result<(), ApiKeyStoreError> {
        sqlx::query("UPDATE api_keys SET last_used_at = $2 WHERE id = $1")
            .bind(id.to_string())
            .bind(at as i64)
            .execute(&self.pool)
            .await
            .map_err(unexpected)?;
        Ok(())
    }

    #[tracing::instrument(name = "Delete an owner's API keys", skip_all)]
    async fn delete_all_for_owner(&self, owner: &Email) -> Result<(), ApiKeyStoreError> {
        sqlx::query!(
            r#"DELETE FROM api_keys WHERE owner = $1"#,
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
    async fn meets_the_api_key_store_contract() {
        let (_postgres, pool) = test_support::postgres::pool().await;
        contract::api_key_store(PostgresApiKeyStore::new(pool)).await;
    }
}
