use secrecy::{ExposeSecret, Secret};
use sqlx::{PgPool, Pool, Postgres, postgres::PgPoolOptions};
use tempered_core::{Email, Password, User, UserStore, UserStoreError, ValidatedUser};

use super::password_hasher::{Argon2Hasher, PasswordVerdict};

/// PostgreSQL-backed [`UserStore`]. Passwords are hashed with Argon2id by
/// an [`Argon2Hasher`]: the OWASP-minimum costs and at most one hash per
/// core at once unless [`with_hasher`](Self::with_hasher) says otherwise.
/// A login whose stored hash was made with other costs saves a new hash.
///
/// ## Migrations
///
/// The crate ships the schema under `tempered_adapters/migrations/`, but
/// [`PostgresUserStore::new`] does **not** run it — the consumer is responsible
/// for migrating the database (the `sqlx::migrate!()` call in this crate is
/// test-only). Run the migrations at startup, e.g.:
///
/// ```ignore
/// sqlx::migrate!("path/to/migrations").run(&pool).await?;
/// let store = PostgresUserStore::new(pool);
/// ```
#[derive(Clone)]
pub struct PostgresUserStore {
    pool: sqlx::PgPool,
    hasher: Argon2Hasher,
}

impl PostgresUserStore {
    pub fn new(pool: Pool<Postgres>) -> Self {
        PostgresUserStore {
            pool,
            hasher: Argon2Hasher::default(),
        }
    }

    /// Hash with `hasher` (its costs and concurrency bound). Existing hashes
    /// keep working, and each is upgraded at its owner's next login.
    pub fn with_hasher(mut self, hasher: Argon2Hasher) -> Self {
        self.hasher = hasher;
        self
    }

    /// Save a new hash for a password that just verified against `old`.
    /// Best effort: the login has already succeeded. The `old` condition
    /// keeps a password changed meanwhile from being overwritten.
    async fn upgrade_hash(&self, email: &Email, old: &str, password: &Password) {
        let result = async {
            let new = self.hasher.hash(password).await?;
            sqlx::query(
                "UPDATE users SET password_hash = $1 WHERE email = $2 AND password_hash = $3",
            )
            .bind(new.expose_secret())
            .bind(email.as_ref().expose_secret())
            .bind(old)
            .execute(&self.pool)
            .await
            .map_err(|e| e.to_string())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!(error = %e, "could not upgrade a password hash");
        }
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    #[tracing::instrument(name = "Adding user to PostgreSQL", skip_all)]
    async fn add_user(&self, user: User) -> Result<(), UserStoreError> {
        let password_hash = self
            .hasher
            .hash(user.password())
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
            if let Some(db_err) = e.as_database_error()
                && db_err.constraint().is_some()
            {
                return UserStoreError::UserAlreadyExists;
            }
            UserStoreError::UnexpectedError(e.to_string())
        })?;

        Ok(())
    }

    #[tracing::instrument(name = "Set 2FA requirement", skip_all)]
    async fn set_requires_2fa(
        &self,
        email: &Email,
        requires_2fa: bool,
    ) -> Result<(), UserStoreError> {
        let query = sqlx::query!(
            r#"
                UPDATE users
                SET requires_2fa = $1
                WHERE email = $2
            "#,
            requires_2fa,
            email.as_ref().expose_secret()
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

    #[tracing::instrument(name = "Set new password", skip_all)]
    async fn set_new_password(
        &self,
        email: &Email,
        new_password: Password,
    ) -> Result<(), UserStoreError> {
        let password_hash = self
            .hasher
            .hash(&new_password)
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

        let updated = query
            .execute(&self.pool)
            .await
            .map_err(|e| UserStoreError::UnexpectedError(e.to_string()))?;

        // No row: the account is gone (deleted since a reset link was sent,
        // say). Report it rather than succeed at changing nothing.
        if updated.rows_affected() == 0 {
            return Err(UserStoreError::UserNotFound);
        }
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
            .map_err(|e| UserStoreError::UnexpectedError(e.to_string()))?;

        let Some(row) = row else {
            // Run a verification against a throwaway hash so the "no such user"
            // path takes the same time as the wrong-password path below. Without
            // this, response latency leaks whether an email is registered.
            self.hasher.verify_nothing(password).await;
            return Err(UserStoreError::UserNotFound);
        };

        // Only a mismatch is a wrong password. A stored hash that does not
        // parse, or a hashing task that died, is the server's fault.
        let stored = Secret::from(row.password_hash);
        let verified = self
            .hasher
            .verify(&stored, password)
            .await
            .map_err(UserStoreError::UnexpectedError)?;
        let PasswordVerdict::Match { needs_rehash } = verified else {
            return Err(UserStoreError::IncorrectPassword);
        };

        let email = Email::try_from(Secret::from(row.email))
            .map_err(|e| UserStoreError::UnexpectedError(e.to_string()))?;
        if needs_rehash {
            self.upgrade_hash(&email, stored.expose_secret(), password)
                .await;
        }
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
            .map_err(|e| UserStoreError::UnexpectedError(e.to_string()))?;

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
    async fn meets_the_user_store_contract() {
        let (_container, pool) = setup_and_connect_db_container().await;
        crate::persistence::contract::user_store(PostgresUserStore::new(pool)).await;
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
    async fn test_set_requires_2fa() {
        let (_container, pool) = setup_and_connect_db_container().await;
        let store = PostgresUserStore::new(pool);
        let user = create_test_user();
        let email = user.email().clone();
        let before = user.requires_2fa();
        store.add_user(user).await.unwrap();

        store.set_requires_2fa(&email, !before).await.unwrap();
        assert_eq!(
            store.get_user(&email).await.unwrap().requires_2fa(),
            !before
        );

        store.set_requires_2fa(&email, before).await.unwrap();
        assert_eq!(store.get_user(&email).await.unwrap().requires_2fa(), before);
    }

    #[tokio::test]
    async fn test_set_requires_2fa_user_not_found() {
        let (_container, pool) = setup_and_connect_db_container().await;
        let store = PostgresUserStore::new(pool);
        let email = Email::try_from(Secret::from("nobody@example.com".to_string())).unwrap();

        let result = store.set_requires_2fa(&email, true).await;
        assert_eq!(result, Err(UserStoreError::UserNotFound));
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

    /// Hashes made with other costs keep working and are upgraded at the
    /// next login.
    #[tokio::test]
    async fn a_login_upgrades_a_hash_made_with_other_costs() {
        use super::super::password_hasher::Argon2Params;
        let (_container, pool) = setup_and_connect_db_container().await;
        let cheap = Argon2Params {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        };
        let old = PostgresUserStore::new(pool.clone()).with_hasher(Argon2Hasher::new(cheap));
        let user = create_test_user();
        let (email, password) = (user.email().clone(), user.password().clone());
        old.add_user(user).await.unwrap();
        let hash_of = |pool: PgPool, email: Email| async move {
            sqlx::query_scalar::<_, String>("SELECT password_hash FROM users WHERE email = $1")
                .bind(email.as_ref().expose_secret().clone())
                .fetch_one(&pool)
                .await
                .unwrap()
        };
        let before = hash_of(pool.clone(), email.clone()).await;
        assert!(before.contains("m=8,t=1,p=1"));

        let new =
            PostgresUserStore::new(pool.clone()).with_hasher(Argon2Hasher::new(Argon2Params {
                iterations: 2,
                ..cheap
            }));
        new.authenticate_user(&email, &password).await.unwrap();
        let after = hash_of(pool.clone(), email.clone()).await;
        assert!(after.contains("m=8,t=2,p=1"), "{after}");
        // The new hash still logs in, and is not rewritten again.
        new.authenticate_user(&email, &password).await.unwrap();
        assert_eq!(hash_of(pool, email).await, after);
    }

    /// A database outage is not "no such user": the login must fail as a
    /// server error, and a caller deciding whether to create an account must
    /// not be told the address is free.
    #[tokio::test]
    async fn an_unreachable_database_is_reported_as_such() {
        let (_container, pool) = setup_and_connect_db_container().await;
        let store = PostgresUserStore::new(pool.clone());
        pool.close().await;
        let email = Email::try_from(Secret::from("a@example.com".to_owned())).unwrap();
        let password = Password::try_from(Secret::from("testpassword123".to_owned())).unwrap();

        assert!(matches!(
            store.authenticate_user(&email, &password).await,
            Err(UserStoreError::UnexpectedError(_))
        ));
        assert!(matches!(
            store.get_user(&email).await,
            Err(UserStoreError::UnexpectedError(_))
        ));
    }

    /// A stored hash that does not parse is the server's fault, not a wrong
    /// password.
    #[tokio::test]
    async fn a_corrupt_stored_hash_is_not_a_wrong_password() {
        let (_container, pool) = setup_and_connect_db_container().await;
        let store = PostgresUserStore::new(pool.clone());
        sqlx::query(
            "INSERT INTO users (email, password_hash, requires_2fa) VALUES ($1, $2, false)",
        )
        .bind("a@example.com")
        .bind("not-a-phc-string")
        .execute(&pool)
        .await
        .unwrap();
        let email = Email::try_from(Secret::from("a@example.com".to_owned())).unwrap();
        let password = Password::try_from(Secret::from("testpassword123".to_owned())).unwrap();

        assert!(matches!(
            store.authenticate_user(&email, &password).await,
            Err(UserStoreError::UnexpectedError(_))
        ));
    }
}
