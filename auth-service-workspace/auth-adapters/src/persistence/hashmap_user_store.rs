use std::collections::HashMap;

use auth_core::{Email, Password, User, UserStore, UserStoreError, ValidatedUser};

#[derive(Default)]
pub struct HashMapUserStore {
    users: HashMap<Email, User>,
}

impl HashMapUserStore {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
        }
    }
}

#[async_trait::async_trait]
impl UserStore for HashMapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.users.contains_key(user.email()) {
            return Err(UserStoreError::UserAlreadyExists);
        }
        self.users.insert(user.email().clone(), user);
        Ok(())
    }

    async fn set_new_password(
        &mut self,
        email: &Email,
        new_password: Password,
    ) -> Result<(), UserStoreError> {
        let user = self
            .users
            .get_mut(email)
            .ok_or(UserStoreError::UserNotFound)?;

        *user = User::new(email.clone(), new_password, user.requires_2fa());
        Ok(())
    }

    async fn authenticate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<ValidatedUser, UserStoreError> {
        let user = self.users.get(email).ok_or(UserStoreError::UserNotFound)?;

        if !user.password_matches(password) {
            return Err(UserStoreError::IncorrectPassword);
        }

        Ok(ValidatedUser::new(email.clone(), user.requires_2fa()))
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        self.users
            .get(email)
            .cloned()
            .ok_or(UserStoreError::UserNotFound)
    }

    async fn delete_user(&mut self, user: &Email) -> Result<(), UserStoreError> {
        self.users
            .remove(user)
            .ok_or(UserStoreError::UserNotFound)?;
        Ok(())
    }
}
