use std::fmt::Debug;

use secrecy::{ExposeSecret, Secret};

use super::user::UserError;

#[derive(Clone)]
pub struct Password(Secret<String>);

/// Fewest characters a password may have.
pub const MIN_PASSWORD_CHARS: usize = 8;
/// Most characters a password may have. Long passphrases fit; a megabyte
/// request body is not hashed and stored. Stored Argon2 hashes also pass
/// through [`Password`] (about 100 characters), so this stays well above.
pub const MAX_PASSWORD_CHARS: usize = 256;

impl TryFrom<Secret<String>> for Password {
    type Error = UserError;

    fn try_from(value: Secret<String>) -> Result<Self, Self::Error> {
        let length = value.expose_secret().chars().count();
        if (MIN_PASSWORD_CHARS..=MAX_PASSWORD_CHARS).contains(&length) {
            Ok(Password(value))
        } else {
            Err(UserError::InvalidPassword)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Password, UserError> {
        Password::try_from(Secret::new(s.to_string()))
    }

    #[test]
    fn length_is_bounded_on_both_sides() {
        assert!(parse("1234567").is_err());
        assert!(parse("12345678").is_ok());
        assert!(parse(&"x".repeat(MAX_PASSWORD_CHARS)).is_ok());
        assert!(parse(&"x".repeat(MAX_PASSWORD_CHARS + 1)).is_err());
    }

    #[test]
    fn a_stored_argon2_hash_fits() {
        // PostgresUserStore loads the PHC string into a Password.
        let phc = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA\
                   $YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXphYmNkZWY";
        assert!(parse(phc).is_ok());
    }
}
