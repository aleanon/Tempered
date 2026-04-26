use std::fmt::Display;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PasswordResetToken(Uuid);

impl PasswordResetToken {
    pub fn new() -> Self {
        PasswordResetToken(Uuid::new_v4())
    }

    pub fn parse(s: &str) -> Option<Self> {
        Uuid::parse_str(s).ok().map(PasswordResetToken)
    }
}

impl Default for PasswordResetToken {
    fn default() -> Self {
        PasswordResetToken::new()
    }
}

impl Display for PasswordResetToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
