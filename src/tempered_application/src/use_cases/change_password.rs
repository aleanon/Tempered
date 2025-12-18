use tempered_core::{Email, Password, UserStore, UserStoreError};

/// Error types for change password use case
#[derive(Debug, thiserror::Error)]
pub enum ChangePasswordError {
    #[error("User store error: {0}")]
    UserStoreError(#[from] UserStoreError),
}

/// Change password use case - updates user's password
pub struct ChangePasswordUseCase<U>
where
    U: UserStore,
{
    user_store: U,
}

impl<U> ChangePasswordUseCase<U>
where
    U: UserStore,
{
    pub fn new(user_store: U) -> Self {
        Self { user_store }
    }

    /// Execute the change password use case
    ///
    /// # Arguments
    /// * `email` - User's email address (from elevated auth token)
    /// * `new_password` - The new password to set
    ///
    /// # Returns
    /// Ok(()) on success, or ChangePasswordError
    #[tracing::instrument(name = "ChangePasswordUseCase::execute", skip(self, new_password))]
    pub async fn execute(
        &self,
        email: Email,
        new_password: Password,
    ) -> Result<(), ChangePasswordError> {
        self.user_store
            .set_new_password(&email, new_password)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::{ExposeSecret, Secret};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tempered_core::{User, ValidatedUser};
    use tokio::sync::RwLock;

    #[derive(Clone)]
    struct MockUserStore {
        users: Arc<RwLock<HashMap<String, Password>>>,
    }

    #[async_trait::async_trait]
    impl UserStore for MockUserStore {
        async fn add_user(&self, _user: User) -> Result<(), UserStoreError> {
            unimplemented!()
        }

        async fn set_new_password(
            &self,
            email: &Email,
            new_password: Password,
        ) -> Result<(), UserStoreError> {
            let email_str = email.as_ref().expose_secret().clone();
            let mut users = self.users.write().await;
            if let Some(password) = users.get_mut(&email_str) {
                *password = new_password;
                Ok(())
            } else {
                Err(UserStoreError::UserNotFound)
            }
        }

        async fn authenticate_user(
            &self,
            _email: &Email,
            _password: &Password,
        ) -> Result<ValidatedUser, UserStoreError> {
            unimplemented!()
        }

        async fn get_user(&self, _email: &Email) -> Result<User, UserStoreError> {
            unimplemented!()
        }

        async fn delete_user(&self, _email: &Email) -> Result<(), UserStoreError> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn test_change_password_success() {
        let email = Email::try_from(Secret::from("test@example.com".to_string())).unwrap();
        let old_password = Password::try_from(Secret::from("old_password".to_string())).unwrap();

        let mut users = HashMap::new();
        users.insert("test@example.com".to_string(), old_password);

        let user_store = MockUserStore {
            users: Arc::new(RwLock::new(users)),
        };

        let use_case = ChangePasswordUseCase::new(user_store.clone());

        let new_password = Password::try_from(Secret::from("new_password".to_string())).unwrap();

        let result = use_case.execute(email.clone(), new_password.clone()).await;
        assert!(result.is_ok());

        // Verify password was changed
        let store = user_store.users.read().await;
        let stored_password = store.get("test@example.com").unwrap();
        assert_eq!(
            stored_password.as_ref().expose_secret(),
            new_password.as_ref().expose_secret()
        );
    }

    #[tokio::test]
    async fn test_change_password_user_not_found() {
        let user_store = MockUserStore {
            users: Arc::new(RwLock::new(HashMap::new())),
        };

        let use_case = ChangePasswordUseCase::new(user_store);

        let email = Email::try_from(Secret::from("test@example.com".to_string())).unwrap();
        let new_password = Password::try_from(Secret::from("new_password".to_string())).unwrap();

        let result = use_case.execute(email, new_password).await;
        assert!(matches!(
            result,
            Err(ChangePasswordError::UserStoreError(
                UserStoreError::UserNotFound
            ))
        ));
    }
}
