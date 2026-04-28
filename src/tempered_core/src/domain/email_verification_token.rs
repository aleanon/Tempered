use std::fmt::Display;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EmailVerificationToken(Uuid);

impl EmailVerificationToken {
    pub fn new() -> Self {
        EmailVerificationToken(Uuid::new_v4())
    }

    pub fn parse(s: &str) -> Option<Self> {
        Uuid::parse_str(s).ok().map(EmailVerificationToken)
    }
}

impl Default for EmailVerificationToken {
    fn default() -> Self {
        EmailVerificationToken::new()
    }
}

impl Display for EmailVerificationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
