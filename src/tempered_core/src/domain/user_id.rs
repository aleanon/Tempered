use std::fmt::Display;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An account's stable identifier. It never changes, not even when the
/// account's address does, so it is what the credential stores, and an
/// app's own tables, should key on. Safe to log and expose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(Uuid);

impl UserId {
    /// A fresh, random id.
    pub fn new() -> Self {
        UserId(Uuid::new_v4())
    }

    pub fn parse(s: &str) -> Option<Self> {
        Uuid::parse_str(s).ok().map(UserId)
    }

    pub fn from_uuid(id: Uuid) -> Self {
        UserId(id)
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for UserId {
    fn default() -> Self {
        UserId::new()
    }
}

impl Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
