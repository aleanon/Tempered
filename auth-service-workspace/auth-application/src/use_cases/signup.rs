use auth_core::{Email, Password, User, UserStore, UserStoreError};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Signup use case - handles user registration
pub struct SignupUseCase<U>
where
    U: UserStore,
{
    user_store: Arc<RwLock<U>>,
}

impl<U> SignupUseCase<U>
where
    U: UserStore,
{
    pub fn new(user_store: Arc<RwLock<U>>) -> Self {
        Self { user_store }
    }

    /// Execute the signup use case
    ///
    /// # Arguments
    /// * `email` - Validated email address
    /// * `password` - Validated password
    /// * `requires_2fa` - Whether user requires 2FA
    ///
    /// # Returns
    /// Ok(()) on success, or UserStoreError if user already exists or other error occurs
    #[tracing::instrument(name = "SignupUseCase::execute", skip(self, password))]
    pub async fn execute(
        &self,
        email: Email,
        password: Password,
        requires_2fa: bool,
    ) -> Result<(), UserStoreError> {
        let user = User::new(email, password, requires_2fa);

        self.user_store.write().await.add_user(user).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::{ExposeSecret, Secret};

    // Mock user store for testing
    struct MockUserStore {
        users: std::collections::HashMap<String, User>,
    }

    #[async_trait::async_trait]
    impl UserStore for MockUserStore {
        async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
            let email = user.email().as_ref().expose_secret().clone();
            if self.users.contains_key(&email) {
                return Err(UserStoreError::UserAlreadyExists);
            }
            self.users.insert(email, user);
            Ok(())
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
        ) -> Result<auth_core::ValidatedUser, UserStoreError> {
            unimplemented!()
        }

        async fn get_user(&self, _email: &Email) -> Result<User, UserStoreError> {
            unimplemented!()
        }

        async fn delete_user(&mut self, _user: &Email) -> Result<(), UserStoreError> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn test_signup_success() {
        let user_store = Arc::new(RwLock::new(MockUserStore {
            users: std::collections::HashMap::new(),
        }));
        let use_case = SignupUseCase::new(user_store);

        let email = Email::try_from(Secret::from("test@example.com".to_string())).unwrap();
        let password = Password::try_from(Secret::from("password123".to_string())).unwrap();

        let result = use_case.execute(email, password, false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_signup_duplicate_user() {
        let mut initial_users = std::collections::HashMap::new();
        let email = Email::try_from(Secret::from("test@example.com".to_string())).unwrap();
        let password = Password::try_from(Secret::from("password123".to_string())).unwrap();
        let user = User::new(email.clone(), password.clone(), false);
        initial_users.insert("test@example.com".to_string(), user);

        let user_store = Arc::new(RwLock::new(MockUserStore {
            users: initial_users,
        }));
        let use_case = SignupUseCase::new(user_store);

        let result = use_case.execute(email, password, false).await;
        assert!(matches!(result, Err(UserStoreError::UserAlreadyExists)));
    }
}
