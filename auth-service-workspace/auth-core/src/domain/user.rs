use secrecy::Secret;
use thiserror::Error;

use super::{email::Email, password::Password};

#[derive(Debug, Error, PartialEq)]
pub enum UserError {
    #[error("Invalid Email")]
    InvalidEmail,
    #[error("Invalid Password: Must be at least 8 characters")]
    InvalidPassword,
}

#[derive(Debug, Clone)]
pub struct User {
    pub email: Email,
    pub password: Password,
    pub requires_2fa: bool,
}

impl User {
    pub fn new(email: Email, password: Password, requires_2fa: bool) -> Self {
        User {
            email,
            password,
            requires_2fa,
        }
    }

    pub fn parse(
        email: Secret<String>,
        password: Secret<String>,
        requires_2fa: bool,
    ) -> Result<Self, UserError> {
        Ok(User {
            email: Email::try_from(email)?,
            password: Password::try_from(password)?,
            requires_2fa,
        })
    }

    pub fn email(&self) -> &Email {
        &self.email
    }

    pub fn password(&self) -> &Password {
        &self.password
    }

    pub fn password_matches(&self, password: &Password) -> bool {
        &self.password == password
    }

    pub fn requires_2fa(&self) -> bool {
        self.requires_2fa
    }
}

impl PartialEq for User {
    fn eq(&self, other: &Self) -> bool {
        self.email == other.email
    }
}

#[derive(Debug, PartialEq)]
pub enum ValidatedUser {
    Requires2Fa(Email),
    No2Fa(Email),
}

impl ValidatedUser {
    pub fn new(email: Email, requires_2fa: bool) -> Self {
        if requires_2fa {
            Self::Requires2Fa(email)
        } else {
            Self::No2Fa(email)
        }
    }

    pub fn email(&self) -> &Email {
        match self {
            Self::Requires2Fa(email) => email,
            Self::No2Fa(email) => email,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eq_only_matches_email() {
        let user1 = User::parse(
            Secret::from("test@example.com".to_owned()),
            Secret::from("passwordpassword123".to_owned()),
            false,
        )
        .unwrap();
        let user2 = User::parse(
            Secret::from("test@example.com".to_owned()),
            Secret::from("passwordpassword".to_owned()),
            true,
        )
        .unwrap();
        let user3 = User::parse(
            Secret::from("test2@example.com".to_owned()),
            Secret::from("passwordpassword".to_owned()),
            false,
        )
        .unwrap();

        assert_eq!(user1, user2);
        assert_ne!(user1, user3);
    }
}
