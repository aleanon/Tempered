//! WebAuthn / passkey ceremony orchestration.
//!
//! The cryptographic verification is a [`tempered_core::WebAuthnVerifier`] port;
//! a production implementation backed by the `webauthn-rs` crate slots in there.

pub mod flow;

pub use flow::{PasskeyFlow, PasskeyFlowError};
