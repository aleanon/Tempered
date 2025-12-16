use auth_core::{Email, UserStore, UserStoreError};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Error types for delete account use case
#[derive(Debug, thiserror::Error)]
pub enum DeleteAccountError {
    #[error("User store error: {0}")]
    UserStoreError(#[from] UserStoreError),
}

/// Delete account use case - removes user account
pub struct DeleteAccountUseCase<U>
where
    U: UserStore,
{
    user_store: Arc<RwLock<U>>,
}

impl<U> DeleteAccountUseCase<U>
where
    U: UserStore,
{
    pub fn new(user_store: Arc<RwLock<U>>) -> Self {
        Self { user_store }
    }

    /// Execute the delete account use case
    ///
    /// # Arguments
    /// * `email` - User's email address (from elevated auth token)
    ///
    /// # Returns
    /// Ok(()) on success, or DeleteAccountError
    #[tracing::instrument(name = "DeleteAccountUseCase::execute", skip(self))]
    pub async fn execute(&self, email: Email) -> Result<(), DeleteAccountError> {
        self.user_store.write().await.delete_user(&email).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auth_core::{Password, User, ValidatedUser};
    use secrecy::{ExposeSecret, Secret};
    use std::collections::HashMap;

    struct MockUserStore {
        users: HashMap<String, User>,
    }

    #[async_trait::async_trait]
    impl UserStore for MockUserStore {
        async fn add_user(&mut self, _user: User) -> Result<(), UserStoreError> {
            unimplemented!()
        }

        async fn set_new_password(
            &mut self,
            _email: &Email,
            _new_password: Password,
        ) -> Result<(), UserStoreError> {
            unimplemented!()
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

        async fn delete_user(&mut self, email: &Email) -> Result<(), UserStoreError> {
            let email_str = email.as_ref().expose_secret().clone();
            if self.users.remove(&email_str).is_some() {
                Ok(())
            } else {
                Err(UserStoreError::UserNotFound)
            }
        }
    }

    #[tokio::test]
    async fn test_delete_account_success() {
        let email = Email::try_from(Secret::from("test@example.com".to_string())).unwrap();
        let password = Password::try_from(Secret::from("password123".to_string())).unwrap();
        let user = User::new(email.clone(), password, false);

        let mut users = HashMap::new();
        users.insert("test@example.com".to_string(), user);

        let user_store = Arc::new(RwLock::new(MockUserStore { users }));

        let use_case = DeleteAccountUseCase::new(user_store.clone());

        let result = use_case.execute(email.clone()).await;
        assert!(result.is_ok());

        // Verify user was deleted
        let store = user_store.read().await;
        assert!(!store.users.contains_key("test@example.com"));
    }

    #[tokio::test]
    async fn test_delete_account_user_not_found() {
        let user_store = Arc::new(RwLock::new(MockUserStore {
            users: HashMap::new(),
        }));

        let use_case = DeleteAccountUseCase::new(user_store);

        let email = Email::try_from(Secret::from("test@example.com".to_string())).unwrap();

        let result = use_case.execute(email).await;
        assert!(matches!(
            result,
            Err(DeleteAccountError::UserStoreError(
                UserStoreError::UserNotFound
            ))
        ));
    }
}
