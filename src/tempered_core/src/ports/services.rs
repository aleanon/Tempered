use async_trait::async_trait;
use thiserror::Error;

use crate::domain::{
    email::Email,
    oauth::{OAuthProviderConfig, OAuthUserInfo},
    passkey::{CredentialId, PasskeyCredential, WebAuthnChallenge},
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
    pub public_key: Vec<u8>,
    pub sign_count: u32,
}

/// Outcome of verifying an authentication assertion.
pub struct VerifiedAssertion {
    pub credential_id: CredentialId,
    pub new_sign_count: u32,
}

/// Port for the WebAuthn cryptographic ceremony (attestation / assertion
/// verification, COSE key handling, signature checks).
///
/// This is the boundary where a real implementation (e.g. backed by the
/// `webauthn-rs` crate) plugs in. Keeping it a port lets the orchestration and
/// storage logic be tested without the heavy crypto dependency, and keeps the
/// core library free of WebAuthn internals.
pub trait WebAuthnVerifier: Send + Sync {
    /// Build the `PublicKeyCredentialCreationOptions` to send to the browser.
    fn start_registration(&self, email: &Email, challenge: &WebAuthnChallenge)
    -> serde_json::Value;

    /// Verify the attestation returned by the browser.
    fn verify_registration(
        &self,
        challenge: &WebAuthnChallenge,
        response: &serde_json::Value,
    ) -> Result<VerifiedRegistration, WebAuthnError>;

    /// Build the `PublicKeyCredentialRequestOptions` to send to the browser.
    fn start_authentication(
        &self,
        allowed: &[CredentialId],
        challenge: &WebAuthnChallenge,
    ) -> serde_json::Value;

    /// Verify an assertion against the stored credential, returning the updated
    /// signature counter (must be strictly greater than the stored value).
    fn verify_authentication(
        &self,
        challenge: &WebAuthnChallenge,
        response: &serde_json::Value,
        stored: &PasskeyCredential,
    ) -> Result<VerifiedAssertion, WebAuthnError>;
}
