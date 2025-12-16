use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordVerifier, Version,
    password_hash::{PasswordHasher, SaltString, rand_core},
};
use auth_core::{Email, Password, User, UserStore, UserStoreError, ValidatedUser};
use secrecy::{ExposeSecret, Secret};
use sqlx::{Pool, Postgres};

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
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
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
        &mut self,
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
    async fn delete_user(&mut self, user: &Email) -> Result<(), UserStoreError> {
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
