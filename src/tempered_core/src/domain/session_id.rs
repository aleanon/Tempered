use std::fmt::Display;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Opaque server-side session identifier.
///
/// Unlike a JWT, this carries no claims — it is a random lookup handle into a
/// `SessionStore`. The session data (and its expiry) live server-side, which is
/// what makes sessions instantly revocable.
///
/// NOTE: backed by a v4 UUID (122 bits of randomness) to match the rest of the
/// codebase. A production hardening step is to widen this to a 256-bit CSPRNG
/// value; the public API here would not change.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(Uuid);

impl SessionId {
    pub fn new() -> Self {
        SessionId(Uuid::new_v4())
    }

    pub fn parse(s: &str) -> Option<Self> {
        Uuid::parse_str(s).ok().map(SessionId)
    }
}

impl Default for SessionId {
    fn default() -> Self {
        SessionId::new()
    }
}

impl Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
