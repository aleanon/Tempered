use std::fmt::Display;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Stable identifier for an issued API key (safe to log / expose).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApiKeyId(Uuid);

impl ApiKeyId {
    pub fn new() -> Self {
        ApiKeyId(Uuid::new_v4())
    }

    pub fn parse(s: &str) -> Option<Self> {
        Uuid::parse_str(s).ok().map(ApiKeyId)
    }
}

impl Default for ApiKeyId {
    fn default() -> Self {
        ApiKeyId::new()
    }
}

impl Display for ApiKeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Split a presented key of the form `"{prefix}.{secret}"` into its parts.
///
/// The non-secret `prefix` is a fast lookup handle into the store; the `secret`
/// is hash-compared against the stored hash. Returns `None` if malformed.
pub fn split_presented_key(presented: &str) -> Option<(&str, &str)> {
    let (prefix, secret) = presented.split_once('.')?;
    if prefix.is_empty() || secret.is_empty() {
        return None;
    }
    Some((prefix, secret))
}
