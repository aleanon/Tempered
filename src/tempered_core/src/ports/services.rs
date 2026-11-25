use async_trait::async_trait;
use thiserror::Error;

use crate::domain::{
    email::Email,
    oauth::{OAuthProviderConfig, OAuthUserInfo, TokenResponse},
    passkey::{CeremonyStart, CeremonyState, CredentialId, PasskeyCredential},
};

/// A message the library sends. Override
/// [`EmailClient::send_mail`] to write your own (HTML, your locale, a link
/// into your app instead of a raw token); the default sends
/// [`subject`](Self::subject) and [`text`](Self::text) through
/// [`EmailClient::send_email`].
#[non_exhaustive]
#[derive(Clone)]
pub enum Mail {
    /// The second-factor code for a login.
    SignInCode { code: crate::TwoFaCode },
    /// The second-factor code for an elevation (a sensitive action).
    ElevationCode { code: crate::TwoFaCode },
    /// A password-reset token (for `/password-reset/complete`).
    PasswordReset { token: String },
    /// An email-verification token (for `/verify-email`).
    VerifyEmail { token: String },
    /// Someone tried to sign up with an address that has an account.
    AlreadyRegistered,
    /// A passwordless sign-in code, and the link to the app's page that
    /// posts it, when the app set one.
    EmailLogin {
        code: crate::TwoFaCode,
        link: Option<String>,
    },
}

/// Only the kind of message: the codes and tokens stay out of logs.
impl std::fmt::Debug for Mail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Mail::SignInCode { .. } => "SignInCode",
            Mail::ElevationCode { .. } => "ElevationCode",
            Mail::PasswordReset { .. } => "PasswordReset",
            Mail::VerifyEmail { .. } => "VerifyEmail",
            Mail::AlreadyRegistered => "AlreadyRegistered",
            Mail::EmailLogin { .. } => "EmailLogin",
        };
        f.write_str(kind)
    }
}

impl Mail {
    /// The default subject line.
    pub fn subject(&self) -> &'static str {
        match self {
            Mail::SignInCode { .. } => "Your sign-in code",
            Mail::ElevationCode { .. } => "Code to confirm a sensitive account action",
            Mail::PasswordReset { .. } => "Password Reset",
            Mail::VerifyEmail { .. } => "Verify your email",
            Mail::AlreadyRegistered => "You already have an account",
            Mail::EmailLogin { .. } => "Your sign-in code",
        }
    }

    /// The default plain-text body.
    pub fn text(&self) -> String {
        match self {
            Mail::SignInCode { code } | Mail::ElevationCode { code } => code.to_string(),
            Mail::PasswordReset { token } | Mail::VerifyEmail { token } => token.clone(),
            Mail::AlreadyRegistered => "Someone tried to create an account with this \
email address, which already has one. If it was you, sign in, or reset your password if \
you have forgotten it. If it was not, you can ignore this message: nothing has changed."
                .to_string(),
            Mail::EmailLogin { code, link: None } => code.to_string(),
            Mail::EmailLogin {
                code,
                link: Some(link),
            } => format!("Your sign-in code is {}, or open {link}", code.as_str()),
        }
    }
}

/// Port trait for email sending service
#[async_trait]
pub trait EmailClient: Send + Sync {
    async fn send_email(
        &self,
        recipient: &Email,
        subject: &str,
        content: &str,
    ) -> Result<(), String>;

    /// Send one of the library's messages. The default renders it with
    /// [`Mail::subject`] and [`Mail::text`]; override this to compose your
    /// own.
    async fn send_mail(&self, recipient: &Email, mail: Mail) -> Result<(), String> {
        self.send_email(recipient, mail.subject(), &mail.text())
            .await
    }
}

#[derive(Debug, Error)]
pub enum OAuthHttpError {
    #[error("Token exchange failed: {0}")]
    TokenExchange(String),
    #[error("Userinfo request failed: {0}")]
    UserInfo(String),
    #[error("Request to the provider failed: {0}")]
    Fetch(String),
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
    ) -> Result<TokenResponse, OAuthHttpError>;

    /// Fetch the user's identity using the access token.
    async fn fetch_user_info(
        &self,
        config: &OAuthProviderConfig,
        access_token: &str,
    ) -> Result<OAuthUserInfo, OAuthHttpError>;

    /// `GET` a JSON document (an OIDC discovery document or a key set).
    async fn fetch_json(&self, url: &str) -> Result<serde_json::Value, OAuthHttpError>;
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
///
/// # What a verifier must check
///
/// The flow around it handles what is not cryptography. It keeps each
/// ceremony single-use and of one kind, looks up the credential by the
/// response's `id`, ties a ceremony started for a user to that user's
/// credentials, and refuses a counter that does not advance. Everything
/// else is the verifier's job, and a verifier that skips a step opens the
/// account it guards. Following the WebAuthn Level 3 verification
/// procedures (§7.1 registration, §7.2 authentication), it must check:
///
/// - **Challenge:** `clientDataJSON.challenge` is the one this ceremony's
///   `state` issued.
/// - **Type:** `clientDataJSON.type` is `webauthn.create` when
///   registering and `webauthn.get` when authenticating.
/// - **Origin:** `clientDataJSON.origin` is one of the app's origins, and
///   `crossOrigin` is not true unless the app allows that.
/// - **Relying party:** `authenticatorData.rpIdHash` is SHA-256 of the
///   app's RP ID.
/// - **User presence and verification:** the UP flag is set, and the UV
///   flag is set when the app requires user verification. A passkey that
///   stands in for 2FA (see `passkey_login_requires_2fa`) needs UV.
/// - **Signature (authentication):** made over `authenticatorData ||
///   SHA-256(clientDataJSON)` with **`stored`'s** public key, never with a
///   key found in the response.
/// - **Credential (authentication):** the response's raw id is `stored`'s
///   [`credential_id`](PasskeyCredential::credential_id), and the returned
///   [`VerifiedAssertion::credential_id`] says so. The flow checks the
///   latter.
/// - **User handle (authentication):** if the response carries a
///   `userHandle`, it is the handle issued for `stored.owner` at
///   registration. A usernameless login has nothing else that ties the
///   assertion to the account.
/// - **Attestation (registration):** the attestation statement verifies,
///   to the level of trust the app asks for (`none` is common for passkeys),
///   and the public key uses an algorithm the app allows.
/// - **Counter:** report the authenticator's signature counter as received.
///   The flow does the comparison.
///
/// The credential ids it returns must use the same encoding as the
/// response's `id` (base64url, as browsers send it), since that is the key
/// the flow looks credentials up by.
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

/// Why a password was refused by a [`PasswordPolicy`].
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("{0}")]
pub struct PasswordRejected(pub String);

/// Extra rules for new passwords (signup, password change, reset), beyond
/// the length rule every [`Password`](crate::Password) already meets.
#[async_trait]
pub trait PasswordPolicy: Send + Sync {
    /// `Err` with a message the user can act on, or `Ok` to accept.
    async fn check(
        &self,
        email: &Email,
        password: &crate::Password,
    ) -> Result<(), PasswordRejected>;
}
