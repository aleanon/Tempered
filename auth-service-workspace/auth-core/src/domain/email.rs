use std::{hash::Hash, sync::LazyLock};

use regex::Regex;
use secrecy::{ExposeSecret, Secret};

use super::user::UserError;

const EMAIL_REGEX_PATTERN: &str = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$";
static EMAIL_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(EMAIL_REGEX_PATTERN).unwrap());

#[derive(Debug, Clone)]
pub struct Email(Secret<String>);

impl TryFrom<Secret<String>> for Email {
    type Error = UserError;

    fn try_from(email: Secret<String>) -> Result<Self, Self::Error> {
        if !EMAIL_REGEX.is_match(&email.expose_secret()) {
            return Err(UserError::InvalidEmail);
        }
        Ok(Email(email))
    }
}

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl AsRef<Secret<String>> for Email {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

impl Eq for Email {
    fn assert_receiver_is_total_eq(&self) {
        self.0.expose_secret().assert_receiver_is_total_eq();
    }
}

impl Hash for Email {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.expose_secret().hash(state);
    }
}
