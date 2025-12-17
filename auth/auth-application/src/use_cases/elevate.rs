use auth_core::{Email, Password, UserStore, UserStoreError};

/// Error types for elevate use case
#[derive(Debug, thiserror::Error)]
pub enum ElevateError {
    #[error("User store error: {0}")]
    UserStoreError(#[from] UserStoreError),
}

/// Elevate use case - grants elevated permissions by re-authenticating
pub struct ElevateUseCase<U>
where
    U: UserStore,
{
    user_store: U,
}

impl<U> ElevateUseCase<U>
where
    U: UserStore,
{
    pub fn new(user_store: U) -> Self {
        Self { user_store }
    }

    /// Execute the elevate use case
    ///
    /// # Arguments
    /// * `email` - User's email address (from existing auth token)
    /// * `password` - User's password for re-authentication
    ///
    /// # Returns
    /// Ok(Email) on successful re-authentication, or ElevateError
    #[tracing::instrument(name = "ElevateUseCase::execute", skip(self, password))]
    pub async fn execute(&self, email: Email, password: Password) -> Result<Email, ElevateError> {
        // Re-authenticate the user
        self.user_store.authenticate_user(&email, &password).await?;

        Ok(email)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auth_core::{User, ValidatedUser};
    use secrecy::{ExposeSecret, Secret};

    #[derive(Clone)]
    struct MockUserStore {
        email: String,
        password: String,
    }

    #[async_trait::async_trait]
    impl UserStore for MockUserStore {
        async fn add_user(&self, _user: User) -> Result<(), UserStoreError> {
            unimplemented!()
        }

        async fn set_new_password(
            &self,
            _email: &Email,
            _new_password: Password,
        ) -> Result<(), UserStoreError> {
            unimplemented!()
        }

        async fn authenticate_user(
            &self,
            email: &Email,
            password: &Password,
        ) -> Result<ValidatedUser, UserStoreError> {
            if email.as_ref().expose_secret() == &self.email
                && password.as_ref().expose_secret() == &self.password
            {
                Ok(ValidatedUser::new(email.clone(), false))
            } else {
                Err(UserStoreError::IncorrectPassword)
            }
        }

        async fn get_user(&self, _email: &Email) -> Result<User, UserStoreError> {
            unimplemented!()
        }

        async fn delete_user(&self, _email: &Email) -> Result<(), UserStoreError> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn test_elevate_success() {
        let user_store = MockUserStore {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
        };

        let use_case = ElevateUseCase::new(user_store);

        let email = Email::try_from(Secret::from("test@example.com".to_string())).unwrap();
        let password = Password::try_from(Secret::from("password123".to_string())).unwrap();

        let result = use_case.execute(email.clone(), password).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), email);
    }

    #[tokio::test]
    async fn test_elevate_wrong_password() {
        let user_store = MockUserStore {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
        };

        let use_case = ElevateUseCase::new(user_store);

        let email = Email::try_from(Secret::from("test@example.com".to_string())).unwrap();
        let password = Password::try_from(Secret::from("wrong_password".to_string())).unwrap();

        let result = use_case.execute(email, password).await;
        assert!(result.is_err());
    }
}
