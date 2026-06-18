use super::email::Email;

/// Base64url credential id assigned by the authenticator.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CredentialId(pub String);

impl CredentialId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A registered passkey (WebAuthn credential) belonging to a user.
///
/// `public_key` is the opaque COSE key produced during registration; this crate
/// never interprets it — signature verification is delegated to a
/// `WebAuthnVerifier`. `sign_count` is the authenticator's monotonic counter,
/// used to detect cloned authenticators.
#[derive(Debug, Clone)]
pub struct PasskeyCredential {
    pub credential_id: CredentialId,
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub owner: Email,
}

/// A single-use WebAuthn challenge issued for a registration or authentication
/// ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WebAuthnChallenge(pub String);

impl WebAuthnChallenge {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
