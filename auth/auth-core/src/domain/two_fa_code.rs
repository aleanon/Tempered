use std::ops::Deref;

use serde::{Deserialize, Serialize};

use super::two_fa_error::TwoFaError;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TwoFaCode(String);

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
}
