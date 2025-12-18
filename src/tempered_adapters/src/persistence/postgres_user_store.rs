use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordVerifier, Version,
    password_hash::{PasswordHasher, SaltString, rand_core},
};
use secrecy::{ExposeSecret, Secret};
use sqlx::{PgPool, Pool, Postgres, postgres::PgPoolOptions};
use tempered_core::{Email, Password, User, UserStore, UserStoreError, ValidatedUser};

#[derive(Clone)]
pub struct PostgresUserStore {
    pool: sqlx::PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: Pool<Postgres>) -> Self {
        PostgresUserStore { pool }
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    #[tracing::instrument(name = "Adding user to PostgreSQL", skip_all)]
    async fn add_user(&self, user: User) -> Result<(), UserStoreError> {
        let password = user.password().clone();
        let password_hash = compute_password_hash(password)
            .await
            .map_err(|e| UserStoreError::UnexpectedError(e.to_string()))?;

        let query = sqlx::query!(
            r#"
                INSERT INTO users (email, password_hash, requires_2fa)
                VALUES ($1, $2, $3)
            "#,
            user.email().as_ref().expose_secret(),
            password_hash.expose_secret(),
            user.requires_2fa()
        );

        query.execute(&self.pool).await.map_err(|e| {
            if let Some(db_err) = e.as_database_error() {
                if db_err.constraint().is_some() {
                    return UserStoreError::UserAlreadyExists;
                }
            }
            UserStoreError::UnexpectedError(e.to_string())
        })?;

        Ok(())
    }

    #[tracing::instrument(name = "Set new password", skip_all)]
    async fn set_new_password(
        &self,
        email: &Email,
        new_password: Password,
    ) -> Result<(), UserStoreError> {
        let password_hash = compute_password_hash(new_password)
            .await
            .map_err(|e| UserStoreError::UnexpectedError(e.to_string()))?;

        let query = sqlx::query!(
            r#"
                UPDATE users
                SET password_hash = $1
                WHERE email = $2
            "#,
            password_hash.expose_secret(),
            email.as_ref().expose_secret()
        );

        query.execute(&self.pool).await.map_err(|e| {
            if let Some(db_err) = e.as_database_error() {
                if db_err.constraint().is_some() {
                    return UserStoreError::UserAlreadyExists;
                }
            }
            UserStoreError::UnexpectedError(e.to_string())
        })?;

        Ok(())
    }

    #[tracing::instrument(name = "Validating user credentials in PostgreSQL", skip_all)]
    async fn authenticate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<ValidatedUser, UserStoreError> {
        let query = sqlx::query!(
            r#"
                SELECT email, password_hash, requires_2fa
                FROM users
                WHERE email = $1
            "#,
            email.as_ref().expose_secret()
        );

        let row = query
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| UserStoreError::UserNotFound)?;

        let Some(row) = row else {
            return Err(UserStoreError::UserNotFound);
        };

        verify_password_hash(Secret::from(row.password_hash), password.clone())
            .await
            .map_err(|_| UserStoreError::IncorrectPassword)?;

        let email = Email::try_from(Secret::from(row.email))
            .map_err(|e| UserStoreError::UnexpectedError(e.to_string()))?;
        Ok(ValidatedUser::new(email, row.requires_2fa))
    }

    #[tracing::instrument(name = "Retrieving user from PostgreSQL", skip_all)]
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        let query = sqlx::query!(
            r#"
                SELECT email, password_hash, requires_2fa
                FROM users
                WHERE email = $1
            "#,
            email.as_ref().expose_secret()
        );

        let row = query
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| UserStoreError::UserNotFound)?;

        let Some(row) = row else {
            return Err(UserStoreError::UserNotFound);
        };

        let user = User::parse(
            Secret::from(row.email),
            Secret::from(row.password_hash),
            row.requires_2fa,
        )
        .map_err(|e| UserStoreError::UnexpectedError(e.to_string()))?;

        Ok(user)
    }

    #[tracing::instrument(name = "Delete user from user store", skip_all)]
    async fn delete_user(&self, user: &Email) -> Result<(), UserStoreError> {
        let query = sqlx::query!(
            r#"
                DELETE FROM users
                WHERE email = $1
            "#,
            user.as_ref().expose_secret()
        );

        let result = query
            .execute(&self.pool)
            .await
            .map_err(|e| UserStoreError::UnexpectedError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(UserStoreError::UserNotFound);
        }

        Ok(())
    }
}

#[tracing::instrument(name = "Verify password hash", skip_all)]
async fn verify_password_hash(
    expected_password_hash: Secret<String>,
    password_candidate: Password,
) -> Result<(), String> {
    let current_span: tracing::Span = tracing::Span::current();
    let result = tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| {
            let expected_password_hash: PasswordHash<'_> =
                PasswordHash::new(expected_password_hash.expose_secret())
                    .map_err(|e| e.to_string())?;

            Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(15000, 2, 1, None).map_err(|e| e.to_string())?,
            )
            .verify_password(
                password_candidate.as_ref().expose_secret().as_bytes(),
                &expected_password_hash,
            )
            .map_err(|e| e.to_string())
        })
    })
    .await
    .map_err(|e| e.to_string())?;

    result
}

#[tracing::instrument(name = "Computing password hash", skip_all)]
async fn compute_password_hash(password: Password) -> Result<Secret<String>, String> {
    let current_span: tracing::Span = tracing::Span::current();

    let result = tokio::task::spawn_blocking(move || {
        current_span.in_scope(move || {
            let salt: SaltString = SaltString::generate(rand_core::OsRng);
            let hasher = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(15000, 2, 1, None).map_err(|e| e.to_string())?,
            );
            hasher
                .hash_password(password.as_ref().expose_secret().as_bytes(), &salt)
                .map(|h| Secret::from(h.to_string()))
                .map_err(|e| e.to_string())
        })
    })
    .await
    .map_err(|e| e.to_string())?;

    result
}

/// Create a PostgreSQL connection pool
///
/// # Arguments
/// * `url` - Database connection URL
///
/// # Returns
/// Result containing the PgPool or an error
pub async fn get_postgres_pool(url: &str, max_connections: u32) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(url)
        .await
}

#[cfg(test)]
mod tests {

    use super::*;
    use secrecy::{ExposeSecret, Secret};
    use sqlx::PgPool;
    use testcontainers_modules::{
        postgres,
        testcontainers::{ContainerAsync, runners::AsyncRunner},
    };

    async fn setup_and_connect_db_container() -> (ContainerAsync<postgres::Postgres>, PgPool) {
        let container = postgres::Postgres::default()
            .start()
            .await
            .expect("Failed to start container");

        let db_port = container
            .get_host_port_ipv4(5432)
            .await
            .expect("Failed to get the mapped port of the container");

        let host = container
            .get_host()
            .await
            .expect("Failed to get the container host address");

        let db_url = format!("postgres://postgres:postgres@{}:{}", host, db_port);

        let connection = get_postgres_pool(&db_url, 5)
            .await
            .expect("Failed to connect to database");

        sqlx::migrate!()
            .run(&connection)
            .await
            .expect("Failed to migrate the database");

        (container, connection)
    }

    fn create_test_user() -> User {
        let unique_id = uuid::Uuid::new_v4();
        User::new(
            Email::try_from(Secret::from(format!("test{}@example.com", unique_id))).unwrap(),
            Password::try_from(Secret::from("password123".to_string())).unwrap(),
            false,
        )
    }

    fn create_test_user_with_2fa() -> User {
        let unique_id = uuid::Uuid::new_v4();
        User::new(
            Email::try_from(Secret::from(format!("test2fa{}@example.com", unique_id))).unwrap(),
            Password::try_from(Secret::from("password123".to_string())).unwrap(),
            true,
        )
    }

    #[tokio::test]
    async fn test_add_user_success() {
        let (_container, pool) = setup_and_connect_db_container().await;
        let store = PostgresUserStore::new(pool.clone());
        let user = create_test_user();

        let result = store.add_user(user.clone()).await;
        assert!(result.is_ok());

        // Verify user was added to database
        let stored_user = store.get_user(user.email()).await;

        assert_eq!(stored_user, Ok(user));
    }

    #[tokio::test]
    async fn test_add_user_duplicate_email() {
        let (_container, pool) = setup_and_connect_db_container().await;
        let store = PostgresUserStore::new(pool);
        let user = create_test_user();

        // Add user first time
        store.add_user(user.clone()).await.unwrap();

        // Try to add same user again
        let result = store.add_user(user).await;
        assert_eq!(result, Err(UserStoreError::UserAlreadyExists));
    }

    #[tokio::test]
    async fn test_authenticate_user_success() {
        let (_container, pool) = setup_and_connect_db_container().await;
        let store = PostgresUserStore::new(pool);
        let user = create_test_user();
        let email = user.email().clone();
        let password = user.password().clone();

        // Add user first
        store.add_user(user).await.unwrap();

        // Authenticate user
        let result = store.authenticate_user(&email, &password).await;
        assert!(result.is_ok());

        let validated_user = result.unwrap();
        assert_eq!(validated_user.email(), &email);
        assert_eq!(validated_user, ValidatedUser::No2Fa(email));
    }

    #[tokio::test]
    async fn test_authenticate_user_with_2fa() {
        let (_container, pool) = setup_and_connect_db_container().await;
        let store = PostgresUserStore::new(pool);
        let user = create_test_user_with_2fa();
        let email = user.email().clone();
        let password = user.password().clone();

        // Add user first
        store.add_user(user).await.unwrap();

        // Authenticate user
        let result = store.authenticate_user(&email, &password).await;
        assert!(result.is_ok());

        let validated_user = result.unwrap();
        assert_eq!(validated_user.email(), &email);
        assert_eq!(validated_user, ValidatedUser::Requires2Fa(email));
    }

    #[tokio::test]
    async fn test_authenticate_user_not_found() {
        let (_container, pool) = setup_and_connect_db_container().await;
        let store = PostgresUserStore::new(pool);
        let email = Email::try_from(Secret::from("nonexistent@example.com".to_string())).unwrap();
        let password = Password::try_from(Secret::from("password123".to_string())).unwrap();

        let result = store.authenticate_user(&email, &password).await;
        assert_eq!(result, Err(UserStoreError::UserNotFound));
    }

    #[tokio::test]
    async fn test_set_new_password() {
        let (_container, pool) = setup_and_connect_db_container().await;
        let store = PostgresUserStore::new(pool);
        let user = create_test_user();
        let email = user.email().clone();
        let new_password = Password::try_from(Secret::from("newpassword123".to_string())).unwrap();

        store.add_user(user).await.unwrap();

        store
            .set_new_password(&email, new_password.clone())
            .await
            .unwrap();

        let result = store.authenticate_user(&email, &new_password).await;
        assert!(result.is_ok());

        let validated_user = result.unwrap();
        assert_eq!(validated_user.email(), &email);
        assert_eq!(validated_user, ValidatedUser::No2Fa(email));
    }

    #[tokio::test]
    async fn test_authenticate_user_wrong_password() {
        let (_container, pool) = setup_and_connect_db_container().await;
        let store = PostgresUserStore::new(pool);
        let user = create_test_user();
        let email = user.email().clone();
        let wrong_password = Password::try_from(Secret::from("wrongpassword".to_string())).unwrap();

        // Add user first
        store.add_user(user).await.unwrap();

        // Try to authenticate with wrong password
        let result = store.authenticate_user(&email, &wrong_password).await;
        assert_eq!(result, Err(UserStoreError::IncorrectPassword));
    }

    #[tokio::test]
    async fn test_get_user_success() {
        let (_container, pool) = setup_and_connect_db_container().await;
        let store = PostgresUserStore::new(pool);
        let user = create_test_user();
        let email = user.email().clone();

        // Add user first
        store.add_user(user.clone()).await.unwrap();

        // Get user
        let result = store.get_user(&email).await;
        assert!(result.is_ok());

        let retrieved_user = result.unwrap();
        assert_eq!(retrieved_user.email(), user.email());
        assert_eq!(retrieved_user.requires_2fa(), user.requires_2fa());
    }

    #[tokio::test]
    async fn test_get_user_not_found() {
        let (_container, pool) = setup_and_connect_db_container().await;
        let store = PostgresUserStore::new(pool);
        let email = Email::try_from(Secret::from("nonexistent@example.com".to_string())).unwrap();

        let result = store.get_user(&email).await;
        assert_eq!(result, Err(UserStoreError::UserNotFound));
    }

    #[tokio::test]
    async fn test_delete_user_success() {
        let (_container, pool) = setup_and_connect_db_container().await;
        let store = PostgresUserStore::new(pool.clone());
        let user = create_test_user();
        let email = user.email().clone();

        // Add user first
        store.add_user(user.clone()).await.unwrap();

        // Delete user
        let result = store.delete_user(&email).await;
        assert!(result.is_ok());

        // Verify user was deleted
        let result = store.get_user(user.email()).await;
        assert_eq!(result, Err(UserStoreError::UserNotFound));
    }

    #[tokio::test]
    async fn test_delete_user_not_found() {
        let (_container, pool) = setup_and_connect_db_container().await;
        let store = PostgresUserStore::new(pool);
        let email = Email::try_from(Secret::from("nonexistent@example.com".to_string())).unwrap();

        let result = store.delete_user(&email).await;
        assert_eq!(result, Err(UserStoreError::UserNotFound));
    }

    #[tokio::test]
    async fn test_compute_password_hash() {
        let password = Password::try_from(Secret::from("testpassword123".to_owned())).unwrap();
        let hash_result = compute_password_hash(password.clone()).await;

        assert!(hash_result.is_ok());
        let hash = hash_result.unwrap();
        assert!(!hash.expose_secret().is_empty());
        assert_ne!(hash.expose_secret(), password.as_ref().expose_secret());
    }

    #[tokio::test]
    async fn test_verify_password_hash_success() {
        let password = Password::try_from(Secret::from("testpassword123".to_owned())).unwrap();
        let hash = compute_password_hash(password.clone()).await.unwrap();

        let result = verify_password_hash(hash, password).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_password_hash_failure() {
        let password = Password::try_from(Secret::from("testpassword123".to_owned())).unwrap();
        let wrong_password = Password::try_from(Secret::from("wrongpassword".to_owned())).unwrap();
        let hash = compute_password_hash(password).await.unwrap();

        let result = verify_password_hash(hash, wrong_password).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_password_hash_invalid_hash() {
        let invalid_hash = Secret::from("invalid_hash_format".to_owned());
        let password = Password::try_from(Secret::from("testpassword123".to_owned())).unwrap();

        let result = verify_password_hash(invalid_hash, password).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_compute_password_hash_deterministic_salt() {
        let password = Password::try_from(Secret::from("testpassword123".to_owned())).unwrap();
        let hash1 = compute_password_hash(password.clone()).await.unwrap();
        let hash2 = compute_password_hash(password.clone()).await.unwrap();

        // Hashes should be different due to random salt
        assert_ne!(hash1.expose_secret(), hash2.expose_secret());

        // But both should verify successfully
        assert!(verify_password_hash(hash1, password.clone()).await.is_ok());
        assert!(verify_password_hash(hash2, password.clone()).await.is_ok());
    }
}
