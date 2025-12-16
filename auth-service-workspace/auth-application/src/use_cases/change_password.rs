use auth_core::{Email, Password, UserStore, UserStoreError};
use std::sync::Arc;
use tokio::sync::RwLock;

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
    user_store: Arc<RwLock<U>>,
}

impl<U> ChangePasswordUseCase<U>
where
    U: UserStore,
{
    pub fn new(user_store: Arc<RwLock<U>>) -> Self {
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
            .write()
            .await
            .set_new_password(&email, new_password)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auth_core::{User, ValidatedUser};
    use secrecy::{ExposeSecret, Secret};
    use std::collections::HashMap;

    struct MockUserStore {
        users: HashMap<String, Password>,
    }

    #[async_trait::async_trait]
    impl UserStore for MockUserStore {
        async fn add_user(&mut self, _user: User) -> Result<(), UserStoreError> {
            unimplemented!()
        }

        async fn set_new_password(
            &mut self,
            email: &Email,
            new_password: Password,
        ) -> Result<(), UserStoreError> {
            let email_str = email.as_ref().expose_secret().clone();
            if let Some(password) = self.users.get_mut(&email_str) {
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

        async fn delete_user(&mut self, _email: &Email) -> Result<(), UserStoreError> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn test_change_password_success() {
        let email = Email::try_from(Secret::from("test@example.com".to_string())).unwrap();
        let old_password = Password::try_from(Secret::from("old_password".to_string())).unwrap();

        let mut users = HashMap::new();
        users.insert("test@example.com".to_string(), old_password);

        let user_store = Arc::new(RwLock::new(MockUserStore { users }));

        let use_case = ChangePasswordUseCase::new(user_store.clone());

        let new_password = Password::try_from(Secret::from("new_password".to_string())).unwrap();

        let result = use_case.execute(email.clone(), new_password.clone()).await;
        assert!(result.is_ok());

        // Verify password was changed
        let store = user_store.read().await;
        let stored_password = store.users.get("test@example.com").unwrap();
        assert_eq!(
            stored_password.as_ref().expose_secret(),
            new_password.as_ref().expose_secret()
        );
    }

    #[tokio::test]
    async fn test_change_password_user_not_found() {
        let user_store = Arc::new(RwLock::new(MockUserStore {
            users: HashMap::new(),
        }));

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
