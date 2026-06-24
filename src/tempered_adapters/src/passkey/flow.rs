//! Framework-agnostic WebAuthn / passkey ceremony orchestration.
//!
//! Like [`OAuthFlow`](crate::oauth::OAuthFlow), this verifies a credential and
//! **yields a domain [`Email`]** rather than issuing a token itself — the app
//! issues whatever token its primary scheme uses.
//!
//! The cryptographic work (attestation/assertion verification, COSE keys) is
//! delegated to a [`WebAuthnVerifier`] port, so the challenge lifecycle, storage
//! and sign-count anti-cloning logic here are all unit-testable offline. A real
//! `webauthn-rs`-backed verifier plugs into that port without changing this code.

use rand::RngCore;
use tempered_core::{
    ChallengeStore, ChallengeStoreError, CredentialId, Email, PasskeyCredential,
    PasskeyCredentialStore, PasskeyStoreError, WebAuthnChallenge, WebAuthnError, WebAuthnVerifier,
};
use thiserror::Error;

#[derive(Clone)]
pub struct PasskeyFlow<CS, ChS, V> {
    credential_store: CS,
    challenge_store: ChS,
    verifier: V,
}

impl<CS, ChS, V> PasskeyFlow<CS, ChS, V>
where
    CS: PasskeyCredentialStore,
    ChS: ChallengeStore,
    V: WebAuthnVerifier,
{
    pub fn new(credential_store: CS, challenge_store: ChS, verifier: V) -> Self {
        Self {
            credential_store,
            challenge_store,
            verifier,
        }
    }

    /// Registration step 1: issue creation options for an enrolling user.
    pub async fn start_registration(
        &self,
        email: Email,
    ) -> Result<serde_json::Value, PasskeyFlowError> {
        let challenge = random_challenge();
        let options = self.verifier.start_registration(&email, &challenge);
        self.challenge_store
            .store_challenge(challenge, Some(email))
            .await?;
        Ok(options)
    }

    /// Registration step 2: verify the attestation and store the credential.
    pub async fn finish_registration(
        &self,
        challenge: WebAuthnChallenge,
        response: serde_json::Value,
    ) -> Result<Email, PasskeyFlowError> {
        let email = self
            .challenge_store
            .consume_challenge(&challenge)
            .await?
            .ok_or(PasskeyFlowError::MissingUser)?;

        let verified = self.verifier.verify_registration(&challenge, &response)?;

        self.credential_store
            .add_credential(PasskeyCredential {
                credential_id: verified.credential_id,
                public_key: verified.public_key,
                sign_count: verified.sign_count,
                owner: email.clone(),
            })
            .await?;

        Ok(email)
    }

    /// Authentication step 1: issue request options. `email = None` for a
    /// usernameless (discoverable-credential) ceremony.
    pub async fn start_authentication(
        &self,
        email: Option<Email>,
    ) -> Result<serde_json::Value, PasskeyFlowError> {
        let allowed: Vec<CredentialId> = match &email {
            Some(e) => self
                .credential_store
                .list_for_user(e)
                .await?
                .into_iter()
                .map(|c| c.credential_id)
                .collect(),
            None => Vec::new(),
        };

        let challenge = random_challenge();
        let options = self.verifier.start_authentication(&allowed, &challenge);
        self.challenge_store.store_challenge(challenge, email).await?;
        Ok(options)
    }

    /// Authentication step 2: verify the assertion, enforce the sign-count
    /// invariant, and return the owning user's email.
    pub async fn finish_authentication(
        &self,
        challenge: WebAuthnChallenge,
        response: serde_json::Value,
    ) -> Result<Email, PasskeyFlowError> {
        // Consume the challenge regardless of the outcome (single use).
        self.challenge_store.consume_challenge(&challenge).await?;

        let cred_id = response
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PasskeyFlowError::Malformed("missing credential id".into()))?;

        let stored = self
            .credential_store
            .get_credential(&CredentialId(cred_id.to_string()))
            .await?;

        let verified = self
            .verifier
            .verify_authentication(&challenge, &response, &stored)?;

        // Detect cloned authenticators: the counter must advance, unless the
        // authenticator does not implement one (both sides remain 0).
        let counter_ok = verified.new_sign_count > stored.sign_count
            || (verified.new_sign_count == 0 && stored.sign_count == 0);
        if !counter_ok {
            return Err(PasskeyFlowError::SignCountRegression);
        }

        self.credential_store
            .update_sign_count(&stored.credential_id, verified.new_sign_count)
            .await?;

        Ok(stored.owner)
    }
}

fn random_challenge() -> WebAuthnChallenge {
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    WebAuthnChallenge(buf.iter().map(|b| format!("{:02x}", b)).collect())
}

#[derive(Debug, Error)]
pub enum PasskeyFlowError {
    #[error("No user bound to challenge")]
    MissingUser,
    #[error("Malformed WebAuthn response: {0}")]
    Malformed(String),
    #[error("Sign count regression (possible cloned authenticator)")]
    SignCountRegression,
    #[error("WebAuthn error: {0}")]
    WebAuthn(#[from] WebAuthnError),
    #[error("Credential store error: {0}")]
    Credential(#[from] PasskeyStoreError),
    #[error("Challenge store error: {0}")]
    Challenge(#[from] ChallengeStoreError),
}

impl tempered_core::IntoStatusMessage for PasskeyFlowError {
    fn into_status_message(self) -> (http::StatusCode, String) {
        match self {
            PasskeyFlowError::MissingUser => (
                http::StatusCode::BAD_REQUEST,
                "No user bound to challenge".to_string(),
            ),
            PasskeyFlowError::Malformed(m) => (http::StatusCode::BAD_REQUEST, m),
            PasskeyFlowError::SignCountRegression => (
                http::StatusCode::UNAUTHORIZED,
                "Sign count regression".to_string(),
            ),
            PasskeyFlowError::WebAuthn(e) => (http::StatusCode::UNAUTHORIZED, e.to_string()),
            PasskeyFlowError::Credential(PasskeyStoreError::CredentialNotFound) => (
                http::StatusCode::UNAUTHORIZED,
                "Unknown credential".to_string(),
            ),
            PasskeyFlowError::Credential(e) => {
                (http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
            PasskeyFlowError::Challenge(ChallengeStoreError::ChallengeNotFound) => (
                http::StatusCode::BAD_REQUEST,
                "Challenge not found or expired".to_string(),
            ),
            PasskeyFlowError::Challenge(e) => {
                (http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::hashmap_challenge_store::HashMapChallengeStore;
    use crate::persistence::hashmap_passkey_credential_store::HashMapPasskeyCredentialStore;
    use secrecy::Secret;
    use serde_json::json;
    use tempered_core::{VerifiedAssertion, VerifiedRegistration};

    /// Deterministic stand-in for a `webauthn-rs`-backed verifier.
    struct MockVerifier;

    impl WebAuthnVerifier for MockVerifier {
        fn start_registration(
            &self,
            _email: &Email,
            challenge: &WebAuthnChallenge,
        ) -> serde_json::Value {
            json!({ "challenge": challenge.as_str() })
        }

        fn verify_registration(
            &self,
            _challenge: &WebAuthnChallenge,
            response: &serde_json::Value,
        ) -> Result<VerifiedRegistration, WebAuthnError> {
            let id = response
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| WebAuthnError::Malformed("no id".into()))?;
            Ok(VerifiedRegistration {
                credential_id: CredentialId(id.to_string()),
                public_key: vec![1, 2, 3],
                sign_count: 0,
            })
        }

        fn start_authentication(
            &self,
            _allowed: &[CredentialId],
            challenge: &WebAuthnChallenge,
        ) -> serde_json::Value {
            json!({ "challenge": challenge.as_str() })
        }

        fn verify_authentication(
            &self,
            _challenge: &WebAuthnChallenge,
            response: &serde_json::Value,
            stored: &PasskeyCredential,
        ) -> Result<VerifiedAssertion, WebAuthnError> {
            let new_sign_count = response
                .get("sign_count")
                .and_then(|v| v.as_u64())
                .map(|n| n as u32)
                .unwrap_or(stored.sign_count + 1);
            Ok(VerifiedAssertion {
                credential_id: stored.credential_id.clone(),
                new_sign_count,
            })
        }
    }

    type Flow = PasskeyFlow<HashMapPasskeyCredentialStore, HashMapChallengeStore, MockVerifier>;

    fn flow() -> Flow {
        PasskeyFlow::new(
            HashMapPasskeyCredentialStore::new(),
            HashMapChallengeStore::new(),
            MockVerifier,
        )
    }

    fn email() -> Email {
        Email::try_from(Secret::new("user@example.com".to_string())).unwrap()
    }

    fn challenge_of(options: &serde_json::Value) -> WebAuthnChallenge {
        WebAuthnChallenge(options["challenge"].as_str().unwrap().to_string())
    }

    async fn register(flow: &Flow, cred_id: &str) {
        let opts = flow.start_registration(email()).await.unwrap();
        let challenge = challenge_of(&opts);
        flow.finish_registration(challenge, json!({ "id": cred_id }))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn register_then_authenticate_returns_owner() {
        let f = flow();
        register(&f, "cred-abc").await;

        let opts = f.start_authentication(Some(email())).await.unwrap();
        let challenge = challenge_of(&opts);
        let who = f
            .finish_authentication(challenge, json!({ "id": "cred-abc", "sign_count": 1 }))
            .await
            .unwrap();
        assert_eq!(who, email());
    }

    #[tokio::test]
    async fn cloned_authenticator_is_rejected_on_counter_regression() {
        let f = flow();
        register(&f, "cred-abc").await;

        // First assertion advances the counter to 5.
        let opts = f.start_authentication(Some(email())).await.unwrap();
        f.finish_authentication(challenge_of(&opts), json!({ "id": "cred-abc", "sign_count": 5 }))
            .await
            .unwrap();

        // A later assertion reporting a lower counter signals a clone.
        let opts = f.start_authentication(Some(email())).await.unwrap();
        let result = f
            .finish_authentication(challenge_of(&opts), json!({ "id": "cred-abc", "sign_count": 3 }))
            .await;
        assert!(matches!(result, Err(PasskeyFlowError::SignCountRegression)));
    }

    #[tokio::test]
    async fn unknown_credential_is_rejected() {
        let f = flow();
        register(&f, "cred-abc").await;

        let opts = f.start_authentication(Some(email())).await.unwrap();
        let result = f
            .finish_authentication(challenge_of(&opts), json!({ "id": "not-registered" }))
            .await;
        assert!(matches!(
            result,
            Err(PasskeyFlowError::Credential(
                PasskeyStoreError::CredentialNotFound
            ))
        ));
    }

    #[tokio::test]
    async fn unknown_challenge_is_rejected() {
        let f = flow();
        let result = f
            .finish_authentication(WebAuthnChallenge("nope".into()), json!({ "id": "x" }))
            .await;
        assert!(matches!(result, Err(PasskeyFlowError::Challenge(_))));
    }
}
