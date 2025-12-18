use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use tempered_core::{Email, Password, User, UserStore, UserStoreError, ValidatedUser};

#[derive(Default, Clone)]
pub struct HashMapUserStore {
    users: Arc<RwLock<HashMap<Email, User>>>,
}

impl HashMapUserStore {
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl UserStore for HashMapUserStore {
    async fn add_user(&self, user: User) -> Result<(), UserStoreError> {
        let mut users = self.users.write().await;
        if users.contains_key(user.email()) {
            return Err(UserStoreError::UserAlreadyExists);
        }
        users.insert(user.email().clone(), user);
        Ok(())
    }

    async fn set_new_password(
        &self,
        email: &Email,
        new_password: Password,
    ) -> Result<(), UserStoreError> {
        let mut users = self.users.write().await;
        let user = users.get_mut(email).ok_or(UserStoreError::UserNotFound)?;

        *user = User::new(email.clone(), new_password, user.requires_2fa());
        Ok(())
    }

    async fn authenticate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<ValidatedUser, UserStoreError> {
        let users = self.users.read().await;
        let user = users.get(email).ok_or(UserStoreError::UserNotFound)?;

        if !user.password_matches(password) {
            return Err(UserStoreError::IncorrectPassword);
        }

        Ok(ValidatedUser::new(email.clone(), user.requires_2fa()))
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        let users = self.users.read().await;
        users
            .get(email)
            .cloned()
            .ok_or(UserStoreError::UserNotFound)
    }

    async fn delete_user(&self, user: &Email) -> Result<(), UserStoreError> {
        let mut users = self.users.write().await;
        users.remove(user).ok_or(UserStoreError::UserNotFound)?;
        Ok(())
    }
}
