use std::{fmt::Display, ops::Deref};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::two_fa_error::TwoFaError;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TwoFaAttemptId(Uuid);

impl TwoFaAttemptId {
    pub fn new() -> Self {
        let id = uuid::Uuid::new_v4();
        TwoFaAttemptId(id)
    }

    pub fn parse(id: &str) -> Result<Self, TwoFaError> {
        Ok(TwoFaAttemptId(
            Uuid::parse_str(id).map_err(|_| TwoFaError::InvalidLoginAttemptID)?,
        ))
    }
}

impl Default for TwoFaAttemptId {
    fn default() -> Self {
        TwoFaAttemptId::new()
    }
}

impl Display for TwoFaAttemptId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Deref for TwoFaAttemptId {
    type Target = Uuid;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
