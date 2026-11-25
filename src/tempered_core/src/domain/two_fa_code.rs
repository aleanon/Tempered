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

    /// A six-digit code (mailed, or from an authenticator app), or a
    /// recovery code: ten letters and digits from the base32 alphabet,
    /// optionally split by `-`, in either case. A recovery code is kept
    /// lowercase without the `-`.
    pub fn parse(code: String) -> Result<Self, TwoFaError> {
        if code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()) {
            return Ok(TwoFaCode(code));
        }
        let recovery: String = code
            .chars()
            .filter(|c| *c != '-')
            .map(|c| c.to_ascii_lowercase())
            .collect();
        if recovery.len() == RECOVERY_CODE_LEN
            && recovery.bytes().all(|b| RECOVERY_ALPHABET.contains(&b))
        {
            Ok(TwoFaCode(recovery))
        } else {
            Err(TwoFaError::InvalidTwoFaCode)
        }
    }

    /// Whether this is a recovery code rather than a six-digit one.
    pub fn is_recovery_code(&self) -> bool {
        self.0.len() == RECOVERY_CODE_LEN
    }

    /// A fresh random recovery code (50 bits), lowercase, without `-`.
    pub fn new_recovery_code() -> Self {
        let code = (0..RECOVERY_CODE_LEN)
            .map(|_| char::from(RECOVERY_ALPHABET[rand::random_range(0..RECOVERY_ALPHABET.len())]))
            .collect();
        TwoFaCode(code)
    }
}

/// Characters in a recovery code: RFC 4648 base32, lowercase (no `0`, `1`,
/// `8` or `9`, so nothing reads as another character).
const RECOVERY_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
/// Length of a recovery code, without separators.
pub const RECOVERY_CODE_LEN: usize = 10;

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
    fn recovery_codes_parse_in_any_case_with_or_without_the_dash() {
        let code = TwoFaCode::parse("ABCDE-23456".to_string()).unwrap();
        assert!(code.is_recovery_code());
        assert_eq!(code, TwoFaCode::parse("abcde23456".to_string()).unwrap());
        assert!(TwoFaCode::parse("abcde-2345".to_string()).is_err());
        assert!(
            TwoFaCode::parse("abcde-23451".to_string()).is_err(),
            "1 is not base32"
        );
        assert!(
            !TwoFaCode::parse("123456".to_string())
                .unwrap()
                .is_recovery_code()
        );
        assert!(TwoFaCode::new_recovery_code().is_recovery_code());
    }

    #[test]
    fn non_ascii_digits_are_not_a_code() {
        assert!(TwoFaCode::parse("١٢٣٤٥٦".to_string()).is_err());
    }

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
