//! The simulated mode's verifier (stand-in for `WebAuthnRsVerifier`).

use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::json;
use tempered::core::{
    CeremonyStart, CeremonyState, CredentialId, PasskeyCredential, VerifiedAssertion,
    VerifiedRegistration, WebAuthnError, WebAuthnVerifier,
};

// ---- Demo verifier (stand-in for a real `webauthn-rs` adapter) -------------
//
// It performs NO cryptography: registration trusts the client-supplied
// credential id, and authentication trusts the asserted sign count. This is only
// safe because the example simulates the authenticator; never ship this.
//
// What it does show is the shape of the port: the verifier issues the challenge
// itself, hands back opaque state for the library to keep server-side between
// the two legs, and gets that state back to finish the ceremony.

#[derive(Clone)]
pub struct DemoVerifier;

static NEXT_CHALLENGE: AtomicU64 = AtomicU64::new(1);

impl DemoVerifier {
    /// A real verifier returns full `PublicKeyCredentialCreationOptions` /
    /// `…RequestOptions` and serialized ceremony state; the simulated frontend
    /// only needs a challenge to echo back.
    fn start(&self) -> CeremonyStart {
        let challenge = format!(
            "demo-challenge-{}",
            NEXT_CHALLENGE.fetch_add(1, Ordering::Relaxed)
        );
        CeremonyStart {
            options: json!({ "challenge": challenge, "rp": { "id": "localhost" } }),
            state: CeremonyState(challenge.into_bytes()),
        }
    }

    /// The one check the demo does make: the response answers *this* ceremony.
    fn check_challenge(
        state: &CeremonyState,
        response: &serde_json::Value,
    ) -> Result<(), WebAuthnError> {
        let echoed = response.get("challenge").and_then(|v| v.as_str());
        if echoed.map(str::as_bytes) == Some(state.0.as_slice()) {
            Ok(())
        } else {
            Err(WebAuthnError::Verification("challenge mismatch".into()))
        }
    }
}

impl WebAuthnVerifier for DemoVerifier {
    fn start_registration(
        &self,
        _user: &tempered::core::Subject,
        _existing: &[PasskeyCredential],
    ) -> Result<CeremonyStart, WebAuthnError> {
        Ok(self.start())
    }

    fn finish_registration(
        &self,
        state: &CeremonyState,
        response: &serde_json::Value,
    ) -> Result<VerifiedRegistration, WebAuthnError> {
        Self::check_challenge(state, response)?;
        let id = credential_id(response)?;
        Ok(VerifiedRegistration {
            credential_id: CredentialId(id),
            // A real verifier stores the public key (or its whole credential).
            credential_data: vec![0xde, 0xad, 0xbe, 0xef],
            sign_count: 0,
        })
    }

    fn start_authentication(
        &self,
        _allowed: &[PasskeyCredential],
    ) -> Result<CeremonyStart, WebAuthnError> {
        Ok(self.start())
    }

    fn finish_authentication(
        &self,
        state: &CeremonyState,
        response: &serde_json::Value,
        stored: &PasskeyCredential,
    ) -> Result<VerifiedAssertion, WebAuthnError> {
        Self::check_challenge(state, response)?;
        // Trust the asserted counter; the flow still enforces monotonicity.
        let new_sign_count = response
            .get("sign_count")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32)
            .unwrap_or(stored.sign_count + 1);
        Ok(VerifiedAssertion {
            credential_id: stored.credential_id.clone(),
            new_sign_count,
            updated_credential_data: None,
        })
    }
}

fn credential_id(response: &serde_json::Value) -> Result<String, WebAuthnError> {
    response
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| WebAuthnError::Malformed("missing credential id".into()))
}
