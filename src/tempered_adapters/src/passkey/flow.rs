//! Framework-agnostic WebAuthn / passkey ceremony orchestration.
//!
//! Like [`OAuthFlow`](crate::oauth::OAuthFlow), this verifies a credential and
//! **yields a domain [`Email`]** rather than issuing a token itself — the app
//! issues whatever token its primary scheme uses.
//!
//! The cryptographic work (challenge generation, attestation/assertion
//! verification, COSE keys) is delegated to a [`WebAuthnVerifier`] port. Each
//! `start_*` asks the verifier for the browser options and an opaque
//! [`CeremonyState`](tempered_core::CeremonyState); the flow parks that state in
//! the [`ChallengeStore`] under a fresh [`CeremonyId`] and hands the id to the
//! client, which echoes it on `finish_*`. The ceremony lifecycle, ownership
//! checks, storage and sign-count anti-cloning logic here are all unit-testable
//! offline with a mock verifier; a `webauthn-rs`-backed one plugs into the same
//! port.

use rand::RngCore;
use tempered_core::{
    CeremonyId, CeremonyKind, ChallengeStore, ChallengeStoreError, ClassifyError, CredentialId,
    Email, ErrorCategory, PasskeyCeremony, PasskeyCredential, PasskeyCredentialStore,
    PasskeyStoreError, PendingCeremony, WebAuthnError, WebAuthnVerifier,
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
    ///
    /// `email` must be the **already-authenticated** user. Enrolling a passkey
    /// grants the ability to log in as that user, so the caller has to prove who
    /// they are first (a logged-in session); never take this value from an
    /// unauthenticated request.
    pub async fn start_registration(
        &self,
        email: Email,
    ) -> Result<PasskeyCeremony, PasskeyFlowError> {
        // Lets the verifier tell the browser which authenticators are already
        // enrolled, so the same one is not registered twice.
        let existing = self.credential_store.list_for_user(&email).await?;
        let start = self.verifier.start_registration(&email, &existing)?;
        self.park(CeremonyKind::Registration, Some(email), start)
            .await
    }

    /// Registration step 2: verify the attestation and store the credential.
    ///
    /// `email` is the authenticated user finishing the ceremony. It must be the
    /// same user who started it: a ceremony begun in one account's session can
    /// not be completed from another's.
    pub async fn finish_registration(
        &self,
        email: &Email,
        ceremony_id: CeremonyId,
        response: serde_json::Value,
    ) -> Result<Email, PasskeyFlowError> {
        let pending = self
            .consume(&ceremony_id, CeremonyKind::Registration)
            .await?;
        let bound = pending.user.ok_or(PasskeyFlowError::MissingUser)?;
        // Reported exactly like an unknown ceremony, so a caller learns nothing
        // about ceremonies that belong to other users.
        if &bound != email {
            return Err(ChallengeStoreError::ChallengeNotFound.into());
        }

        let verified = self
            .verifier
            .finish_registration(&pending.state, &response)?;

        self.credential_store
            .add_credential(PasskeyCredential {
                credential_id: verified.credential_id,
                credential_data: verified.credential_data,
                sign_count: verified.sign_count,
                owner: bound.clone(),
                name: None,
            })
            .await
            .map_err(|e| match e {
                PasskeyStoreError::CredentialAlreadyExists => {
                    PasskeyFlowError::CredentialAlreadyRegistered
                }
                other => other.into(),
            })?;

        Ok(bound)
    }

    /// Authentication step 1: issue request options. `email = None` for a
    /// usernameless (discoverable-credential) ceremony.
    pub async fn start_authentication(
        &self,
        email: Option<Email>,
    ) -> Result<PasskeyCeremony, PasskeyFlowError> {
        let allowed = match &email {
            Some(e) => self.credential_store.list_for_user(e).await?,
            None => Vec::new(),
        };
        let start = self.verifier.start_authentication(&allowed)?;
        self.park(CeremonyKind::Authentication, email, start).await
    }

    /// Authentication step 2: verify the assertion, enforce the sign-count
    /// invariant, and return the owning user's email.
    pub async fn finish_authentication(
        &self,
        ceremony_id: CeremonyId,
        response: serde_json::Value,
    ) -> Result<Email, PasskeyFlowError> {
        Ok(self
            .finish_authentication_with_credential(ceremony_id, response)
            .await?
            .0)
    }

    /// [`finish_authentication`](Self::finish_authentication), also returning
    /// which credential answered, so the caller can
    /// [`confirm_enrolled`](Self::confirm_enrolled) it later.
    pub async fn finish_authentication_with_credential(
        &self,
        ceremony_id: CeremonyId,
        response: serde_json::Value,
    ) -> Result<(Email, CredentialId), PasskeyFlowError> {
        // Consume the ceremony regardless of the outcome (single use).
        let pending = self
            .consume(&ceremony_id, CeremonyKind::Authentication)
            .await?;

        let cred_id = response
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PasskeyFlowError::Malformed("missing credential id".into()))?;

        let stored = self
            .credential_store
            .get_credential(&CredentialId(cred_id.to_string()))
            .await?;

        // A ceremony started for one user can only be answered with one of that
        // user's credentials. (Usernameless ceremonies carry no user; there the
        // credential alone identifies the account.)
        if let Some(expected) = &pending.user
            && &stored.owner != expected
        {
            return Err(PasskeyFlowError::WrongCredential);
        }

        let verified = self
            .verifier
            .finish_authentication(&pending.state, &response, &stored)?;
        // The verifier must have checked the assertion against the
        // credential that was looked up, not some other one.
        if verified.credential_id != stored.credential_id {
            return Err(PasskeyFlowError::WrongCredential);
        }

        // Detect cloned authenticators: the counter must advance, unless the
        // authenticator does not implement one (both sides remain 0).
        let counter_ok = verified.new_sign_count > stored.sign_count
            || (verified.new_sign_count == 0 && stored.sign_count == 0);
        if !counter_ok {
            return Err(PasskeyFlowError::SignCountRegression);
        }

        self.credential_store
            .update_after_authentication(
                &stored.credential_id,
                verified.new_sign_count,
                verified.updated_credential_data,
            )
            .await
            .map_err(|e| match e {
                // Another login with the same counter got there first.
                PasskeyStoreError::SignCountNotAdvanced => PasskeyFlowError::SignCountRegression,
                other => other.into(),
            })?;

        Ok((stored.owner, stored.credential_id))
    }

    /// Check that `credential_id` is still enrolled for `owner`.
    ///
    /// A usernameless login only learns whose account it is from the
    /// credential itself, so the caller cannot open the login (take its
    /// ticket) before the credential is read. It opens the login once the
    /// owner is known and then calls this: a credential removed in between
    /// fails here, one removed afterwards is caught by the ticket.
    pub async fn confirm_enrolled(
        &self,
        owner: &Email,
        credential_id: &CredentialId,
    ) -> Result<(), PasskeyFlowError> {
        let stored = self.credential_store.get_credential(credential_id).await?;
        if &stored.owner != owner {
            return Err(PasskeyFlowError::WrongCredential);
        }
        Ok(())
    }

    /// Remove every passkey enrolled for `email`. Call when the account is
    /// deleted, so its credentials cannot outlive it or be inherited by a later
    /// account that reuses the address.
    ///
    /// Enrolments the user has started but not finished are dropped too, so
    /// one begun before this call cannot add a passkey after it.
    /// The user's credentials.
    pub async fn list(&self, email: &Email) -> Result<Vec<PasskeyCredential>, PasskeyFlowError> {
        Ok(self.credential_store.list_for_user(email).await?)
    }

    /// Rename one of the user's credentials.
    pub async fn rename(
        &self,
        email: &Email,
        id: &CredentialId,
        name: Option<String>,
    ) -> Result<bool, PasskeyFlowError> {
        Ok(self
            .credential_store
            .rename_credential(email, id, name)
            .await?)
    }

    /// Remove one of the user's credentials.
    pub async fn remove(&self, email: &Email, id: &CredentialId) -> Result<bool, PasskeyFlowError> {
        Ok(self.credential_store.delete_credential(email, id).await?)
    }

    pub async fn forget_user(&self, email: &Email) -> Result<(), PasskeyFlowError> {
        self.challenge_store.delete_all_for_user(email).await?;
        Ok(self.credential_store.delete_all_for_user(email).await?)
    }

    /// Keep a started ceremony's state server-side under a fresh id, and return
    /// what the client needs: the id and the browser options.
    async fn park(
        &self,
        kind: CeremonyKind,
        user: Option<Email>,
        start: tempered_core::CeremonyStart,
    ) -> Result<PasskeyCeremony, PasskeyFlowError> {
        let ceremony_id = random_ceremony_id();
        self.challenge_store
            .store_ceremony(
                ceremony_id.clone(),
                PendingCeremony {
                    kind,
                    user,
                    state: start.state,
                },
            )
            .await?;
        Ok(PasskeyCeremony {
            ceremony_id,
            options: start.options,
        })
    }
}

impl<CS, ChS, V> PasskeyFlow<CS, ChS, V>
where
    ChS: ChallengeStore,
{
    /// Take the ceremony `id` out of the store (it is single use), as long as
    /// it is a `kind` ceremony. One of the other kind is reported exactly like
    /// an unknown one, and is spent all the same.
    async fn consume(
        &self,
        id: &CeremonyId,
        kind: CeremonyKind,
    ) -> Result<PendingCeremony, PasskeyFlowError> {
        let pending = self.challenge_store.consume_ceremony(id).await?;
        if pending.kind != kind {
            return Err(ChallengeStoreError::ChallengeNotFound.into());
        }
        Ok(pending)
    }
}

fn random_ceremony_id() -> CeremonyId {
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    CeremonyId(buf.iter().map(|b| format!("{:02x}", b)).collect())
}

#[derive(Debug, Error)]
pub enum PasskeyFlowError {
    #[error("No user bound to ceremony")]
    MissingUser,
    #[error("Credential does not belong to the user the ceremony was started for")]
    WrongCredential,
    #[error("Credential id is already registered")]
    CredentialAlreadyRegistered,
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

impl ClassifyError for PasskeyFlowError {
    fn classify(self) -> (ErrorCategory, String) {
        match self {
            PasskeyFlowError::MissingUser => (
                ErrorCategory::BadRequest,
                "No user bound to ceremony".to_string(),
            ),
            // Same answer as an unknown credential: do not reveal whose it is.
            PasskeyFlowError::WrongCredential => (
                ErrorCategory::Unauthorized,
                "Unknown credential".to_string(),
            ),
            PasskeyFlowError::CredentialAlreadyRegistered => (
                ErrorCategory::Conflict,
                "Credential is already registered".to_string(),
            ),
            PasskeyFlowError::Malformed(m) => (ErrorCategory::BadRequest, m),
            PasskeyFlowError::SignCountRegression => (
                ErrorCategory::Unauthorized,
                "Sign count regression".to_string(),
            ),
            // The verifier's reason (bad signature, wrong origin, ...) is for
            // the log; the client learns only that the assertion failed.
            PasskeyFlowError::WebAuthn(e) => {
                tracing::info!(error = %e, "passkey verification failed");
                (
                    ErrorCategory::Unauthorized,
                    "Passkey verification failed".to_string(),
                )
            }
            PasskeyFlowError::Credential(PasskeyStoreError::CredentialNotFound) => (
                ErrorCategory::Unauthorized,
                "Unknown credential".to_string(),
            ),
            PasskeyFlowError::Credential(e) => {
                tracing::error!(error = %e, "passkey credential store error");
                (ErrorCategory::Internal, "Internal error".to_string())
            }
            PasskeyFlowError::Challenge(ChallengeStoreError::ChallengeNotFound) => (
                ErrorCategory::BadRequest,
                "Challenge not found or expired".to_string(),
            ),
            PasskeyFlowError::Challenge(e) => {
                tracing::error!(error = %e, "passkey challenge store error");
                (ErrorCategory::Internal, "Internal error".to_string())
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! A deterministic stand-in for a real (`webauthn-rs`-backed) verifier,
    //! shared by the flow and scheme tests.

    use std::sync::atomic::{AtomicU64, Ordering};

    use serde_json::{Value, json};
    use tempered_core::{
        CeremonyStart, CeremonyState, CredentialId, Email, PasskeyCredential, VerifiedAssertion,
        VerifiedRegistration, WebAuthnError, WebAuthnVerifier,
    };

    /// Issues its own challenge per ceremony (as real verifiers do), keeps it as
    /// the ceremony state, and only accepts a response that echoes it:
    /// `{ "id": <credential id>, "challenge": <options.challenge>, "sign_count"?: n }`.
    #[derive(Clone, Default)]
    pub struct MockVerifier;

    static NEXT_CHALLENGE: AtomicU64 = AtomicU64::new(1);

    fn start() -> CeremonyStart {
        let challenge = format!(
            "challenge-{}",
            NEXT_CHALLENGE.fetch_add(1, Ordering::Relaxed)
        );
        CeremonyStart {
            options: json!({ "challenge": challenge }),
            state: CeremonyState(challenge.into_bytes()),
        }
    }

    fn check_challenge(state: &CeremonyState, response: &Value) -> Result<(), WebAuthnError> {
        let echoed = response.get("challenge").and_then(|v| v.as_str());
        if echoed.map(str::as_bytes) == Some(state.0.as_slice()) {
            Ok(())
        } else {
            Err(WebAuthnError::Verification("challenge mismatch".into()))
        }
    }

    impl WebAuthnVerifier for MockVerifier {
        fn start_registration(
            &self,
            _email: &Email,
            _existing: &[PasskeyCredential],
        ) -> Result<CeremonyStart, WebAuthnError> {
            Ok(start())
        }

        fn finish_registration(
            &self,
            state: &CeremonyState,
            response: &Value,
        ) -> Result<VerifiedRegistration, WebAuthnError> {
            check_challenge(state, response)?;
            let id = response
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| WebAuthnError::Malformed("no id".into()))?;
            Ok(VerifiedRegistration {
                credential_id: CredentialId(id.to_string()),
                credential_data: vec![1, 2, 3],
                sign_count: 0,
            })
        }

        fn start_authentication(
            &self,
            _allowed: &[PasskeyCredential],
        ) -> Result<CeremonyStart, WebAuthnError> {
            Ok(start())
        }

        fn finish_authentication(
            &self,
            state: &CeremonyState,
            response: &Value,
            stored: &PasskeyCredential,
        ) -> Result<VerifiedAssertion, WebAuthnError> {
            check_challenge(state, response)?;
            let new_sign_count = response
                .get("sign_count")
                .and_then(|v| v.as_u64())
                .map(|n| n as u32)
                .unwrap_or(stored.sign_count + 1);
            Ok(VerifiedAssertion {
                credential_id: stored.credential_id.clone(),
                new_sign_count,
                // Exercise the "verifier rewrites its credential data" path.
                updated_credential_data: Some(vec![9, new_sign_count as u8]),
            })
        }
    }

    /// The authenticator's reply to a started ceremony, for the mock verifier.
    pub fn reply(ceremony: &tempered_core::PasskeyCeremony, cred_id: &str) -> Value {
        json!({ "id": cred_id, "challenge": ceremony.options["challenge"] })
    }

    /// Like [`reply`], asserting a specific signature counter.
    pub fn reply_with_count(
        ceremony: &tempered_core::PasskeyCeremony,
        cred_id: &str,
        sign_count: u32,
    ) -> Value {
        json!({
            "id": cred_id,
            "challenge": ceremony.options["challenge"],
            "sign_count": sign_count
        })
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{MockVerifier, reply, reply_with_count};
    use super::*;
    use crate::persistence::hashmap_challenge_store::HashMapChallengeStore;
    use crate::persistence::hashmap_passkey_credential_store::HashMapPasskeyCredentialStore;
    use secrecy::Secret;
    use serde_json::json;

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

    fn other_email() -> Email {
        Email::try_from(Secret::new("attacker@example.com".to_string())).unwrap()
    }

    async fn register_for(flow: &Flow, who: Email, cred_id: &str) {
        let ceremony = flow.start_registration(who.clone()).await.unwrap();
        let response = reply(&ceremony, cred_id);
        flow.finish_registration(&who, ceremony.ceremony_id, response)
            .await
            .unwrap();
    }

    async fn register(flow: &Flow, cred_id: &str) {
        register_for(flow, email(), cred_id).await;
    }

    #[tokio::test]
    async fn registration_cannot_be_finished_by_a_different_user() {
        let f = flow();
        let ceremony = f.start_registration(email()).await.unwrap();
        let response = reply(&ceremony, "cred-evil");

        let result = f
            .finish_registration(&other_email(), ceremony.ceremony_id, response)
            .await;
        assert!(matches!(
            result,
            Err(PasskeyFlowError::Challenge(
                ChallengeStoreError::ChallengeNotFound
            ))
        ));
        // Nothing was enrolled for either user.
        assert!(
            f.credential_store
                .get_credential(&CredentialId("cred-evil".into()))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn register_then_authenticate_returns_owner() {
        let f = flow();
        register(&f, "cred-abc").await;

        let ceremony = f.start_authentication(Some(email())).await.unwrap();
        let response = reply_with_count(&ceremony, "cred-abc", 1);
        let who = f
            .finish_authentication(ceremony.ceremony_id, response)
            .await
            .unwrap();
        assert_eq!(who, email());
    }

    #[tokio::test]
    async fn the_ceremony_id_is_not_the_verifiers_challenge() {
        let f = flow();
        let ceremony = f.start_registration(email()).await.unwrap();
        // The verifier's challenge travels in the options; the id is only a
        // server-side lookup handle.
        assert_ne!(
            ceremony.options["challenge"].as_str().unwrap(),
            ceremony.ceremony_id.as_str()
        );
        assert_eq!(ceremony.ceremony_id.as_str().len(), 64);
    }

    #[tokio::test]
    async fn a_response_to_a_different_ceremony_is_rejected() {
        let f = flow();
        register(&f, "cred-abc").await;

        // Two concurrent login ceremonies; the reply to the first is presented
        // against the second's id, so the verifier sees the wrong state.
        let first = f.start_authentication(Some(email())).await.unwrap();
        let second = f.start_authentication(Some(email())).await.unwrap();
        let reply_to_first = reply(&first, "cred-abc");

        let result = f
            .finish_authentication(second.ceremony_id, reply_to_first)
            .await;
        assert!(matches!(result, Err(PasskeyFlowError::WebAuthn(_))));
    }

    #[tokio::test]
    async fn a_ceremony_is_single_use() {
        let f = flow();
        register(&f, "cred-abc").await;

        let ceremony = f.start_authentication(Some(email())).await.unwrap();
        let response = reply_with_count(&ceremony, "cred-abc", 1);
        f.finish_authentication(ceremony.ceremony_id.clone(), response.clone())
            .await
            .unwrap();

        let replay = f
            .finish_authentication(ceremony.ceremony_id, response)
            .await;
        assert!(matches!(
            replay,
            Err(PasskeyFlowError::Challenge(
                ChallengeStoreError::ChallengeNotFound
            ))
        ));
    }

    #[tokio::test]
    async fn a_failed_attempt_still_consumes_the_ceremony() {
        let f = flow();
        register(&f, "cred-abc").await;

        let ceremony = f.start_authentication(Some(email())).await.unwrap();
        let bad = json!({ "id": "cred-abc", "challenge": "wrong" });
        assert!(
            f.finish_authentication(ceremony.ceremony_id.clone(), bad)
                .await
                .is_err()
        );

        // The correct reply can no longer be used with that ceremony.
        let good = reply(&ceremony, "cred-abc");
        let retry = f.finish_authentication(ceremony.ceremony_id, good).await;
        assert!(matches!(retry, Err(PasskeyFlowError::Challenge(_))));
    }

    #[tokio::test]
    async fn a_ceremony_for_one_user_rejects_another_users_credential() {
        let f = flow();
        register(&f, "cred-victim").await;
        register_for(&f, other_email(), "cred-attacker").await;

        // Started for the victim, answered with the attacker's own credential.
        let ceremony = f.start_authentication(Some(email())).await.unwrap();
        let response = reply(&ceremony, "cred-attacker");
        let result = f
            .finish_authentication(ceremony.ceremony_id, response)
            .await;
        assert!(matches!(result, Err(PasskeyFlowError::WrongCredential)));
    }

    #[tokio::test]
    async fn usernameless_ceremony_identifies_the_user_by_credential() {
        let f = flow();
        register(&f, "cred-abc").await;

        let ceremony = f.start_authentication(None).await.unwrap();
        let response = reply(&ceremony, "cred-abc");
        let who = f
            .finish_authentication(ceremony.ceremony_id, response)
            .await
            .unwrap();
        assert_eq!(who, email());
    }

    #[tokio::test]
    async fn an_existing_credential_id_cannot_be_re_registered() {
        let f = flow();
        register(&f, "cred-abc").await;

        // Another account tries to enroll the same credential id.
        let ceremony = f.start_registration(other_email()).await.unwrap();
        let response = reply(&ceremony, "cred-abc");
        let result = f
            .finish_registration(&other_email(), ceremony.ceremony_id, response)
            .await;
        assert!(matches!(
            result,
            Err(PasskeyFlowError::CredentialAlreadyRegistered)
        ));

        // The credential still belongs to its original owner.
        let stored = f
            .credential_store
            .get_credential(&CredentialId("cred-abc".into()))
            .await
            .unwrap();
        assert_eq!(stored.owner, email());
    }

    #[tokio::test]
    async fn forgetting_a_user_removes_only_their_credentials() {
        let f = flow();
        register(&f, "cred-a").await;
        register(&f, "cred-b").await;
        register_for(&f, other_email(), "cred-other").await;

        f.forget_user(&email()).await.unwrap();
        // Idempotent.
        f.forget_user(&email()).await.unwrap();

        assert!(
            f.credential_store
                .list_for_user(&email())
                .await
                .unwrap()
                .is_empty()
        );
        let ceremony = f.start_authentication(None).await.unwrap();
        let response = reply(&ceremony, "cred-a");
        assert!(matches!(
            f.finish_authentication(ceremony.ceremony_id, response)
                .await,
            Err(PasskeyFlowError::Credential(
                PasskeyStoreError::CredentialNotFound
            ))
        ));

        // The other user's passkey is untouched.
        assert_eq!(
            f.credential_store
                .list_for_user(&other_email())
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn authentication_persists_counter_and_updated_credential_data() {
        let f = flow();
        register(&f, "cred-abc").await;

        let ceremony = f.start_authentication(Some(email())).await.unwrap();
        let response = reply_with_count(&ceremony, "cred-abc", 7);
        f.finish_authentication(ceremony.ceremony_id, response)
            .await
            .unwrap();

        let stored = f
            .credential_store
            .get_credential(&CredentialId("cred-abc".into()))
            .await
            .unwrap();
        assert_eq!(stored.sign_count, 7);
        assert_eq!(stored.credential_data, vec![9, 7]);
    }

    #[tokio::test]
    async fn cloned_authenticator_is_rejected_on_counter_regression() {
        let f = flow();
        register(&f, "cred-abc").await;

        // First assertion advances the counter to 5.
        let ceremony = f.start_authentication(Some(email())).await.unwrap();
        let response = reply_with_count(&ceremony, "cred-abc", 5);
        f.finish_authentication(ceremony.ceremony_id, response)
            .await
            .unwrap();

        // A later assertion reporting a lower counter signals a clone.
        let ceremony = f.start_authentication(Some(email())).await.unwrap();
        let response = reply_with_count(&ceremony, "cred-abc", 3);
        let result = f
            .finish_authentication(ceremony.ceremony_id, response)
            .await;
        assert!(matches!(result, Err(PasskeyFlowError::SignCountRegression)));
    }

    #[tokio::test]
    async fn unknown_credential_is_rejected() {
        let f = flow();
        register(&f, "cred-abc").await;

        let ceremony = f.start_authentication(Some(email())).await.unwrap();
        let response = reply(&ceremony, "not-registered");
        let result = f
            .finish_authentication(ceremony.ceremony_id, response)
            .await;
        assert!(matches!(
            result,
            Err(PasskeyFlowError::Credential(
                PasskeyStoreError::CredentialNotFound
            ))
        ));
    }

    #[tokio::test]
    async fn unknown_ceremony_is_rejected() {
        let f = flow();
        let result = f
            .finish_authentication(CeremonyId("nope".into()), json!({ "id": "x" }))
            .await;
        assert!(matches!(result, Err(PasskeyFlowError::Challenge(_))));
    }

    /// Says it verified a credential other than the one it was handed.
    #[derive(Clone)]
    struct OtherCredentialVerifier;

    impl WebAuthnVerifier for OtherCredentialVerifier {
        fn start_registration(
            &self,
            email: &Email,
            existing: &[PasskeyCredential],
        ) -> Result<tempered_core::CeremonyStart, WebAuthnError> {
            MockVerifier.start_registration(email, existing)
        }
        fn finish_registration(
            &self,
            state: &tempered_core::CeremonyState,
            response: &serde_json::Value,
        ) -> Result<tempered_core::VerifiedRegistration, WebAuthnError> {
            MockVerifier.finish_registration(state, response)
        }
        fn start_authentication(
            &self,
            allowed: &[PasskeyCredential],
        ) -> Result<tempered_core::CeremonyStart, WebAuthnError> {
            MockVerifier.start_authentication(allowed)
        }
        fn finish_authentication(
            &self,
            state: &tempered_core::CeremonyState,
            response: &serde_json::Value,
            stored: &PasskeyCredential,
        ) -> Result<tempered_core::VerifiedAssertion, WebAuthnError> {
            let mut verified = MockVerifier.finish_authentication(state, response, stored)?;
            verified.credential_id = CredentialId("someone-elses".to_string());
            Ok(verified)
        }
    }

    #[tokio::test]
    async fn an_assertion_verified_for_another_credential_is_refused() {
        let f = PasskeyFlow::new(
            HashMapPasskeyCredentialStore::new(),
            HashMapChallengeStore::new(),
            OtherCredentialVerifier,
        );
        let ceremony = f.start_registration(email()).await.unwrap();
        f.finish_registration(
            &email(),
            ceremony.ceremony_id.clone(),
            reply(&ceremony, "cred-1"),
        )
        .await
        .unwrap();

        let login = f.start_authentication(None).await.unwrap();
        let result = f
            .finish_authentication(
                login.ceremony_id.clone(),
                reply_with_count(&login, "cred-1", 1),
            )
            .await;
        assert!(matches!(result, Err(PasskeyFlowError::WrongCredential)));
    }

    /// A login ceremony is not an enrolment. Finishing it as one would store
    /// a credential against a challenge issued for signing in; the verifier
    /// is not what should catch that (this test's verifier does not).
    #[tokio::test]
    async fn a_login_ceremony_cannot_be_finished_as_an_enrolment() {
        let f = flow();
        register(&f, "cred-1").await;
        let login = f.start_authentication(Some(email())).await.unwrap();

        let result = f
            .finish_registration(&email(), login.ceremony_id.clone(), reply(&login, "cred-2"))
            .await;
        assert!(matches!(
            result,
            Err(PasskeyFlowError::Challenge(
                ChallengeStoreError::ChallengeNotFound
            ))
        ));
        // And it is spent: it cannot be used as a login afterwards either.
        let result = f
            .finish_authentication(
                login.ceremony_id.clone(),
                reply_with_count(&login, "cred-1", 1),
            )
            .await;
        assert!(matches!(result, Err(PasskeyFlowError::Challenge(_))));
    }

    #[tokio::test]
    async fn an_enrolment_ceremony_cannot_be_finished_as_a_login() {
        let f = flow();
        register(&f, "cred-1").await;
        let enrolment = f.start_registration(email()).await.unwrap();

        let result = f
            .finish_authentication(
                enrolment.ceremony_id.clone(),
                reply_with_count(&enrolment, "cred-1", 1),
            )
            .await;
        assert!(matches!(
            result,
            Err(PasskeyFlowError::Challenge(
                ChallengeStoreError::ChallengeNotFound
            ))
        ));
    }
}
