use async_trait::async_trait;
use thiserror::Error;

use crate::domain::{
    email::Email,
    oauth::{OAuthProviderConfig, OAuthUserInfo},
    passkey::{CeremonyStart, CeremonyState, CredentialId, PasskeyCredential},
};

/// Port trait for email sending service
#[async_trait]
pub trait EmailClient: Send + Sync {
    async fn send_email(
        &self,
        recipient: &Email,
        subject: &str,
        content: &str,
    ) -> Result<(), String>;
}

#[derive(Debug, Error)]
pub enum OAuthHttpError {
    #[error("Token exchange failed: {0}")]
    TokenExchange(String),
    #[error("Userinfo request failed: {0}")]
    UserInfo(String),
}

/// Port for the outbound HTTP calls an OAuth2 flow makes to a provider.
///
/// Abstracted as a trait so the flow can be unit-tested with a mock client
/// (no network) while production uses a real `reqwest`-backed implementation.
#[async_trait]
pub trait OAuthHttpClient: Send + Sync {
    /// Exchange an authorization `code` for an access token.
    ///
    /// `code_verifier` is the PKCE verifier (RFC 7636) whose S256 challenge was
    /// sent on the authorize redirect; implementations must send it as the
    /// `code_verifier` form field so the provider can bind the code to the
    /// request that started the flow.
    async fn exchange_code(
        &self,
        config: &OAuthProviderConfig,
        code: &str,
        code_verifier: &str,
    ) -> Result<String, OAuthHttpError>;

    /// Fetch the user's identity using the access token.
    async fn fetch_user_info(
        &self,
        config: &OAuthProviderConfig,
        access_token: &str,
    ) -> Result<OAuthUserInfo, OAuthHttpError>;
}

#[derive(Debug, Error)]
pub enum WebAuthnError {
    #[error("WebAuthn verification failed: {0}")]
    Verification(String),
    #[error("Malformed WebAuthn response: {0}")]
    Malformed(String),
}

/// Outcome of verifying a registration attestation.
pub struct VerifiedRegistration {
    pub credential_id: CredentialId,
    /// Opaque data the verifier needs to check later assertions; stored as
    /// [`PasskeyCredential::credential_data`].
    pub credential_data: Vec<u8>,
    pub sign_count: u32,
}

/// Outcome of verifying an authentication assertion.
pub struct VerifiedAssertion {
    pub credential_id: CredentialId,
    pub new_sign_count: u32,
    /// Replacement for the stored [`PasskeyCredential::credential_data`], when
    /// the verifier keeps mutable state in it (e.g. its own copy of the counter
    /// or backup flags). `None` leaves the stored data untouched.
    pub updated_credential_data: Option<Vec<u8>>,
}

/// Port for the WebAuthn cryptographic ceremony (challenge generation,
/// attestation / assertion verification, COSE key handling, signature checks).
///
/// This is the boundary where a real implementation (e.g. backed by the
/// `webauthn-rs` crate) plugs in. Keeping it a port lets the orchestration and
/// storage logic be tested without the heavy crypto dependency, and keeps the
/// core library free of WebAuthn internals.
///
/// The verifier **owns the challenge**: each `start_*` generates one, embeds it
/// in the returned options, and returns whatever it must remember as an opaque
/// [`CeremonyState`]. The caller stores that state server-side and passes it
/// back to the matching `finish_*`. This is the shape WebAuthn libraries expose
/// (they do not accept an externally generated challenge), and it keeps
/// challenge generation next to the code that verifies it.
pub trait WebAuthnVerifier: Send + Sync {
    /// Start enrolling a credential for `email`.
    ///
    /// `existing` are the user's current credentials, so the verifier can list
    /// them as `excludeCredentials` and stop the same authenticator being
    /// enrolled twice.
    fn start_registration(
        &self,
        email: &Email,
        existing: &[PasskeyCredential],
    ) -> Result<CeremonyStart, WebAuthnError>;

    /// Verify the attestation the browser returned for the ceremony `state`
    /// was created for.
    fn finish_registration(
        &self,
        state: &CeremonyState,
        response: &serde_json::Value,
    ) -> Result<VerifiedRegistration, WebAuthnError>;

    /// Start an authentication ceremony.
    ///
    /// `allowed` are the credentials that may answer it; an empty slice asks
    /// for a usernameless (discoverable-credential) ceremony.
    fn start_authentication(
        &self,
        allowed: &[PasskeyCredential],
    ) -> Result<CeremonyStart, WebAuthnError>;

    /// Verify an assertion against the stored credential, for the ceremony
    /// `state` was created for, returning the authenticator's new signature
    /// counter.
    fn finish_authentication(
        &self,
        state: &CeremonyState,
        response: &serde_json::Value,
        stored: &PasskeyCredential,
    ) -> Result<VerifiedAssertion, WebAuthnError>;
}
