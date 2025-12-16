use std::fmt::Debug;

use secrecy::{ExposeSecret, Secret};

use super::user::UserError;

#[derive(Clone)]
pub struct Password(Secret<String>);

impl TryFrom<Secret<String>> for Password {
    type Error = UserError;

    fn try_from(value: Secret<String>) -> Result<Self, Self::Error> {
        if value.expose_secret().as_str().len() < 8 {
            Err(UserError::InvalidPassword)
        } else {
            Ok(Password(value))
        }
    }
}

impl AsRef<Secret<String>> for Password {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret().as_str() == other.0.expose_secret().as_str()
    }
}

impl Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password(*Masked*)")
    }
}
