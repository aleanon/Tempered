//! WebAuthn / passkey ceremony orchestration.
//!
//! The cryptographic verification is a [`tempered_core::WebAuthnVerifier`] port.
//! The production implementation, `WebAuthnRsVerifier`, is backed by the
//! `webauthn-rs` crate (feature `passkeys-webauthn`).

pub mod flow;
#[cfg(feature = "passkeys-webauthn")]
pub mod webauthn_rs_verifier;

pub use flow::{PasskeyFlow, PasskeyFlowError};
/// The `webauthn-rs` crate, for building a custom [`webauthn_rs::Webauthn`]
/// (more origins, a timeout, an RP name) to hand to
/// [`WebAuthnRsVerifier::from_webauthn`].
#[cfg(feature = "passkeys-webauthn")]
pub use webauthn_rs;
#[cfg(feature = "passkeys-webauthn")]
pub use webauthn_rs_verifier::{MIN_USER_HANDLE_KEY_BYTES, WebAuthnRsVerifier};
