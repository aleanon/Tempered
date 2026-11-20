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

fn unexpected(e: impl std::fmt::Display) -> ApiKeyStoreError {
    ApiKeyStoreError::UnexpectedError(e.to_string())
}

fn parse_id(value: &str) -> Result<ApiKeyId, ApiKeyStoreError> {
    ApiKeyId::parse(value).ok_or_else(|| unexpected(format!("malformed key id {value:?}")))
}

#[async_trait::async_trait]
impl ApiKeyStore for PostgresApiKeyStore {
    #[tracing::instrument(name = "Create API key", skip_all)]
    async fn create_key(&self, record: ApiKeyRecord) -> Result<(), ApiKeyStoreError> {
        sqlx::query!(
            r#"
                INSERT INTO api_keys (id, prefix, secret_hash, owner, scopes)
                VALUES ($1, $2, $3, $4, $5)
            "#,
            record.id.to_string(),
            record.prefix,
            record.secret_hash,
            record.owner.as_ref().expose_secret(),
            &record.scopes
        )
        .execute(&self.pool)
        .await
        .map_err(unexpected)?;
        Ok(())
    }

    #[tracing::instrument(name = "Find API key", skip_all)]
    async fn find_by_prefix(&self, prefix: &str) -> Result<ApiKeyRecord, ApiKeyStoreError> {
        let row = sqlx::query!(
            r#"SELECT id, prefix, secret_hash, owner, scopes FROM api_keys WHERE prefix = $1"#,
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
        })
    }

    #[tracing::instrument(name = "Revoke API key", skip_all)]
    async fn revoke_key(&self, id: &ApiKeyId) -> Result<(), ApiKeyStoreError> {
        let deleted = sqlx::query!(r#"DELETE FROM api_keys WHERE id = $1"#, id.to_string())
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
            r#"SELECT id, prefix, scopes FROM api_keys WHERE owner = $1"#,
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
            })
        })
        .collect()
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
