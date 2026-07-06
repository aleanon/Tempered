use std::ops::Deref;

use serde::{Deserialize, Serialize};

use super::two_fa_error::TwoFaError;
use crate::util::constant_time_eq;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFaCode(String);

/// Equality is constant-time: one side of a 2FA check is always
/// attacker-supplied, and a timing difference would leak how many leading
/// digits matched. Implemented on the type so every store gets it for free.
impl PartialEq for TwoFaCode {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

impl Eq for TwoFaCode {}

impl TwoFaCode {
    pub fn new() -> Self {
        let mut code = String::with_capacity(6);

        for _ in 0..6 {
            let digit: u8 = rand::random_range(0..10);
            code.push(char::from(b'0' + digit));
        }

        TwoFaCode(code)
    }

    pub fn parse(code: String) -> Result<Self, TwoFaError> {
        if code.len() != 6 || !code.chars().all(|c| c.is_numeric()) {
            Err(TwoFaError::InvalidTwoFaCode)
        } else {
            Ok(TwoFaCode(code.to_string()))
        }
    }
}

impl Default for TwoFaCode {
    fn default() -> Self {
        TwoFaCode::new()
    }
}

impl Deref for TwoFaCode {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        for _ in 0..100 {
            let code = TwoFaCode::new();
            dbg!("{}", &code.0);
            assert_eq!(code.len(), 6);
            assert!(code.0.chars().all(|c| c.is_numeric()))
        }
    }

    #[test]
    fn equality_matches_value_semantics() {
        let a = TwoFaCode::parse("123456".to_string()).unwrap();
        let b = TwoFaCode::parse("123456".to_string()).unwrap();
        let c = TwoFaCode::parse("123457".to_string()).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
