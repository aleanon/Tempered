//! The production [`WebAuthnVerifier`], backed by `webauthn-rs`.
//!
//! `webauthn-rs` performs the WebAuthn §7.1/§7.2 checks the port lists:
//! challenge, type, origin, RP ID hash, user presence and verification
//! (passkeys always require UV), the signature with the stored key, and the
//! attestation (`none` for passkeys). This adapter adds the two checks that
//! tie a response to the credential the flow looked up: the raw credential
//! id and the user handle.

use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tempered_core::{
    CeremonyStart, CeremonyState, CredentialId, PasskeyCredential, Subject, UserId,
    VerifiedAssertion, VerifiedRegistration, WebAuthnError, WebAuthnVerifier,
};
use webauthn_rs::prelude::{
    DiscoverableAuthentication, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, Url, Uuid, Webauthn, WebauthnBuilder,
};

/// The shortest user-handle key accepted, in bytes.
pub const MIN_USER_HANDLE_KEY_BYTES: usize = 32;

/// A [`WebAuthnVerifier`] over a [`Webauthn`] instance.
///
/// **User handles.** WebAuthn gives each account an opaque user handle,
/// stored on the authenticator and returned on usernameless logins. It must
/// not reveal who the user is, and must not change with the address: it is
/// an HMAC-SHA256 of the account's id under a secret key, cut to a UUID (so
/// a passkey keeps working after an email change). Keep the key stable (load
/// it from the environment like the JWT secret): a new key changes every
/// handle, and passkeys enrolled under the old one stop logging in.
#[derive(Clone)]
pub struct WebAuthnRsVerifier {
    webauthn: Arc<Webauthn>,
    user_handle_key: Arc<Secret<Vec<u8>>>,
}

impl WebAuthnRsVerifier {
    /// A verifier for relying party `rp_id` (the site's domain, such as
    /// `example.com`) served at `rp_origin` (such as
    /// `https://example.com`), with `webauthn-rs`'s defaults.
    ///
    /// # Errors
    ///
    /// If `rp_origin` is not a URL or `webauthn-rs` refuses the pair (the
    /// origin must be on `rp_id` or a subdomain of it).
    ///
    /// # Panics
    ///
    /// If `user_handle_key` is shorter than [`MIN_USER_HANDLE_KEY_BYTES`].
    pub fn new(
        rp_id: &str,
        rp_origin: &str,
        user_handle_key: Secret<Vec<u8>>,
    ) -> Result<Self, WebAuthnError> {
        let origin = Url::parse(rp_origin)
            .map_err(|e| WebAuthnError::Malformed(format!("rp_origin: {e}")))?;
        let webauthn = WebauthnBuilder::new(rp_id, &origin)
            .and_then(WebauthnBuilder::build)
            .map_err(|e| WebAuthnError::Verification(format!("relying party: {e}")))?;
        Ok(Self::from_webauthn(webauthn, user_handle_key))
    }

    /// A verifier over a `Webauthn` you built yourself (see the re-exported
    /// [`webauthn_rs`](crate::passkey::webauthn_rs) for more origins, a
    /// timeout or an RP name).
    ///
    /// # Panics
    ///
    /// If `user_handle_key` is shorter than [`MIN_USER_HANDLE_KEY_BYTES`].
    pub fn from_webauthn(webauthn: Webauthn, user_handle_key: Secret<Vec<u8>>) -> Self {
        let length = user_handle_key.expose_secret().len();
        assert!(
            length >= MIN_USER_HANDLE_KEY_BYTES,
            "the passkey user-handle key is {length} bytes; use at least {MIN_USER_HANDLE_KEY_BYTES} random bytes"
        );
        Self {
            webauthn: Arc::new(webauthn),
            user_handle_key: Arc::new(user_handle_key),
        }
    }

    /// The user handle for the account `user`.
    fn user_handle(&self, user: &UserId) -> Uuid {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.user_handle_key.expose_secret())
            .expect("HMAC takes a key of any length");
        mac.update(user.as_uuid().as_bytes());
        let digest = mac.finalize().into_bytes();
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        // Mark it as a version 8 (custom) UUID, as RFC 9562 asks.
        uuid::Builder::from_custom_bytes(bytes).into_uuid()
    }
}

/// What `start_*` hands the flow to keep, as JSON inside [`CeremonyState`].
#[derive(Serialize, Deserialize)]
enum State {
    Registration(PasskeyRegistration),
    /// A login offered to the listed credentials.
    Authentication(PasskeyAuthentication),
    /// A usernameless login, answered by whichever passkey the user picks.
    Discoverable(DiscoverableAuthentication),
}

fn encode_state(state: &State) -> Result<CeremonyState, WebAuthnError> {
    serde_json::to_vec(state)
        .map(CeremonyState)
        .map_err(|e| WebAuthnError::Verification(format!("could not save the ceremony: {e}")))
}

fn decode_state(state: &CeremonyState) -> Result<State, WebAuthnError> {
    serde_json::from_slice(&state.0)
        .map_err(|e| WebAuthnError::Malformed(format!("ceremony state: {e}")))
}

fn passkey(credential: &PasskeyCredential) -> Result<Passkey, WebAuthnError> {
    serde_json::from_slice(&credential.credential_data)
        .map_err(|e| WebAuthnError::Malformed(format!("stored passkey: {e}")))
}

fn to_json<T: Serialize>(value: &T) -> Result<serde_json::Value, WebAuthnError> {
    serde_json::to_value(value).map_err(|e| WebAuthnError::Verification(e.to_string()))
}

fn credential_id(raw: &[u8]) -> CredentialId {
    CredentialId(URL_SAFE_NO_PAD.encode(raw))
}

fn refused(e: impl std::fmt::Display) -> WebAuthnError {
    WebAuthnError::Verification(e.to_string())
}

/// The signature counter inside a passkey. `webauthn-rs` has no getter for
/// it, but documents the serialised form as stable for storage.
fn counter_of(passkey: &Passkey) -> u32 {
    serde_json::to_value(passkey)
        .ok()
        .and_then(|v| {
            v.pointer("/cred/counter")
                .and_then(serde_json::Value::as_u64)
        })
        .and_then(|c| u32::try_from(c).ok())
        .unwrap_or(0)
}

impl WebAuthnVerifier for WebAuthnRsVerifier {
    fn start_registration(
        &self,
        user: &Subject,
        existing: &[PasskeyCredential],
    ) -> Result<CeremonyStart, WebAuthnError> {
        let exclude = existing
            .iter()
            .map(|c| passkey(c).map(|p| p.cred_id().clone()))
            .collect::<Result<Vec<_>, _>>()?;
        let name = user.email.as_ref().expose_secret();
        let (options, state) = self
            .webauthn
            .start_passkey_registration(self.user_handle(&user.id), name, name, Some(exclude))
            .map_err(refused)?;
        Ok(CeremonyStart {
            options: to_json(&options)?,
            state: encode_state(&State::Registration(state))?,
        })
    }

    fn finish_registration(
        &self,
        state: &CeremonyState,
        response: &serde_json::Value,
    ) -> Result<VerifiedRegistration, WebAuthnError> {
        let State::Registration(state) = decode_state(state)? else {
            return Err(WebAuthnError::Verification(
                "not a registration ceremony".to_string(),
            ));
        };
        let response: RegisterPublicKeyCredential = serde_json::from_value(response.clone())
            .map_err(|e| WebAuthnError::Malformed(e.to_string()))?;
        let passkey = self
            .webauthn
            .finish_passkey_registration(&response, &state)
            .map_err(refused)?;
        Ok(VerifiedRegistration {
            credential_id: credential_id(passkey.cred_id().as_ref()),
            sign_count: counter_of(&passkey),
            credential_data: serde_json::to_vec(&passkey).map_err(refused)?,
        })
    }

    fn start_authentication(
        &self,
        allowed: &[PasskeyCredential],
    ) -> Result<CeremonyStart, WebAuthnError> {
        let (options, state) = if allowed.is_empty() {
            let (options, state) = self
                .webauthn
                .start_discoverable_authentication()
                .map_err(refused)?;
            (to_json(&options)?, State::Discoverable(state))
        } else {
            let passkeys = allowed.iter().map(passkey).collect::<Result<Vec<_>, _>>()?;
            let (options, state) = self
                .webauthn
                .start_passkey_authentication(&passkeys)
                .map_err(refused)?;
            (to_json(&options)?, State::Authentication(state))
        };
        Ok(CeremonyStart {
            options,
            state: encode_state(&state)?,
        })
    }

    fn finish_authentication(
        &self,
        state: &CeremonyState,
        response: &serde_json::Value,
        stored: &PasskeyCredential,
    ) -> Result<VerifiedAssertion, WebAuthnError> {
        let response: PublicKeyCredential = serde_json::from_value(response.clone())
            .map_err(|e| WebAuthnError::Malformed(e.to_string()))?;

        // The response must be from the credential the flow looked up...
        if credential_id(response.get_credential_id()) != stored.credential_id {
            return Err(WebAuthnError::Verification(
                "the response is from another credential".to_string(),
            ));
        }
        // ...and, when it names a user, from that credential's owner.
        let expected_handle = self.user_handle(&stored.owner);
        if let Some(handle) = response.get_user_unique_id()
            && handle != expected_handle.as_bytes()
        {
            return Err(WebAuthnError::Verification(
                "the response names another user".to_string(),
            ));
        }

        let mut passkey = passkey(stored)?;
        let result = match decode_state(state)? {
            State::Authentication(state) => self
                .webauthn
                .finish_passkey_authentication(&response, &state),
            State::Discoverable(state) => {
                // A usernameless login has only the user handle to bind the
                // assertion to the account: it must be there.
                if response.get_user_unique_id().is_none() {
                    return Err(WebAuthnError::Verification(
                        "a usernameless login must name its user".to_string(),
                    ));
                }
                self.webauthn
                    .finish_discoverable_authentication_v2(&response, state, &passkey)
            }
            State::Registration(_) => {
                return Err(WebAuthnError::Verification(
                    "not an authentication ceremony".to_string(),
                ));
            }
        }
        .map_err(refused)?;

        let changed = passkey.update_credential(&result) == Some(true);
        Ok(VerifiedAssertion {
            credential_id: credential_id(result.cred_id().as_ref()),
            new_sign_count: result.counter(),
            updated_credential_data: if changed {
                Some(serde_json::to_vec(&passkey).map_err(refused)?)
            } else {
                None
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passkey::{PasskeyFlow, PasskeyFlowError};
    use crate::persistence::{HashMapChallengeStore, HashMapPasskeyCredentialStore};
    use tempered_core::{PasskeyCeremony, PasskeyCredentialStore};
    use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
    use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

    const ORIGIN: &str = "https://example.com";

    type Flow =
        PasskeyFlow<HashMapPasskeyCredentialStore, HashMapChallengeStore, WebAuthnRsVerifier>;

    fn verifier() -> WebAuthnRsVerifier {
        WebAuthnRsVerifier::new("example.com", ORIGIN, Secret::new(vec![7; 32])).unwrap()
    }

    fn flow() -> (Flow, HashMapPasskeyCredentialStore) {
        let credentials = HashMapPasskeyCredentialStore::new();
        let flow = PasskeyFlow::new(
            credentials.clone(),
            HashMapChallengeStore::new(),
            verifier(),
        );
        (flow, credentials)
    }

    /// An account at `s`, with a fresh id.
    fn email(s: &str) -> Subject {
        Subject {
            id: UserId::new(),
            email: tempered_core::Email::try_from(Secret::new(s.to_string())).unwrap(),
        }
    }

    /// A software authenticator that performs user verification.
    fn authenticator() -> SoftPasskey {
        SoftPasskey::new(true)
    }

    fn create(device: &mut SoftPasskey, ceremony: &PasskeyCeremony) -> serde_json::Value {
        let options: CreationChallengeResponse =
            serde_json::from_value(ceremony.options.clone()).unwrap();
        let response = device
            .do_registration(Url::parse(ORIGIN).unwrap(), options)
            .unwrap();
        serde_json::to_value(response).unwrap()
    }

    fn get(device: &mut SoftPasskey, ceremony: &PasskeyCeremony) -> serde_json::Value {
        let options: RequestChallengeResponse =
            serde_json::from_value(ceremony.options.clone()).unwrap();
        let response = device
            .do_authentication(Url::parse(ORIGIN).unwrap(), options)
            .unwrap();
        serde_json::to_value(response).unwrap()
    }

    async fn enrol(flow: &Flow, device: &mut SoftPasskey, user: &Subject) {
        let ceremony = flow.start_registration(user.clone()).await.unwrap();
        let response = create(device, &ceremony);
        flow.finish_registration(user, ceremony.ceremony_id, response)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_real_passkey_enrols_and_logs_in() {
        let (flow, credentials) = flow();
        let mut device = authenticator();
        let alice = email("alice@example.com");
        enrol(&flow, &mut device, &alice).await;

        let stored = credentials.list_for_user(&alice.id).await.unwrap();
        assert_eq!(stored.len(), 1);

        for _ in 0..2 {
            let ceremony = flow
                .start_authentication(Some(alice.clone()))
                .await
                .unwrap();
            let response = get(&mut device, &ceremony);
            let who = flow
                .finish_authentication(ceremony.ceremony_id, response)
                .await
                .unwrap();
            assert_eq!(who, alice.id);
        }
    }

    #[tokio::test]
    async fn an_assertion_is_good_for_one_ceremony_only() {
        let (flow, _) = flow();
        let mut device = authenticator();
        let alice = email("alice@example.com");
        enrol(&flow, &mut device, &alice).await;

        let first = flow
            .start_authentication(Some(alice.clone()))
            .await
            .unwrap();
        let response = get(&mut device, &first);
        flow.finish_authentication(first.ceremony_id, response.clone())
            .await
            .unwrap();

        // The same signed response, offered to a fresh ceremony: its
        // challenge is not this ceremony's.
        let second = flow
            .start_authentication(Some(alice.clone()))
            .await
            .unwrap();
        let result = flow
            .finish_authentication(second.ceremony_id, response)
            .await;
        assert!(matches!(
            result,
            Err(PasskeyFlowError::WebAuthn(WebAuthnError::Verification(_)))
        ));
    }

    #[tokio::test]
    async fn a_counter_that_goes_backwards_is_refused() {
        let (flow, credentials) = flow();
        let mut device = authenticator();
        let alice = email("alice@example.com");
        enrol(&flow, &mut device, &alice).await;
        let id = credentials.list_for_user(&alice.id).await.unwrap()[0]
            .credential_id
            .clone();

        // As if a clone of this authenticator had already logged in far
        // ahead of it.
        credentials
            .update_after_authentication(&id, 1000, None)
            .await
            .unwrap();

        let ceremony = flow
            .start_authentication(Some(alice.clone()))
            .await
            .unwrap();
        let response = get(&mut device, &ceremony);
        let result = flow
            .finish_authentication(ceremony.ceremony_id, response)
            .await;
        assert!(matches!(result, Err(PasskeyFlowError::SignCountRegression)));
    }

    #[tokio::test]
    async fn a_response_naming_another_user_is_refused() {
        let (flow, _) = flow();
        let mut device = authenticator();
        let alice = email("alice@example.com");
        enrol(&flow, &mut device, &alice).await;

        let ceremony = flow
            .start_authentication(Some(alice.clone()))
            .await
            .unwrap();
        let mut response = get(&mut device, &ceremony);
        // The user handle is not covered by the signature, so only this
        // adapter's check stops a swapped one.
        let other = verifier().user_handle(&email("mallory@example.com").id);
        response["response"]["userHandle"] =
            serde_json::Value::String(URL_SAFE_NO_PAD.encode(other.as_bytes()));
        let result = flow
            .finish_authentication(ceremony.ceremony_id, response)
            .await;
        assert!(matches!(
            result,
            Err(PasskeyFlowError::WebAuthn(WebAuthnError::Verification(_)))
        ));
    }

    #[tokio::test]
    async fn the_same_authenticator_cannot_enrol_twice() {
        let (flow, _) = flow();
        let mut device = authenticator();
        let alice = email("alice@example.com");
        enrol(&flow, &mut device, &alice).await;

        let ceremony = flow.start_registration(alice.clone()).await.unwrap();
        let excluded = ceremony.options["publicKey"]["excludeCredentials"]
            .as_array()
            .map_or(0, Vec::len);
        assert_eq!(excluded, 1, "the enrolled passkey is excluded");
    }

    #[test]
    fn user_handles_are_stable_per_user_and_key() {
        let v = verifier();
        let a = email("alice@example.com");
        assert_eq!(v.user_handle(&a.id), v.user_handle(&a.id));
        assert_ne!(
            v.user_handle(&a.id),
            v.user_handle(&email("bob@example.com").id)
        );
        let other_key =
            WebAuthnRsVerifier::new("example.com", ORIGIN, Secret::new(vec![8; 32])).unwrap();
        assert_ne!(v.user_handle(&a.id), other_key.user_handle(&a.id));
    }

    #[test]
    #[should_panic(expected = "use at least 32 random bytes")]
    fn a_short_user_handle_key_is_refused_at_startup() {
        let _ = WebAuthnRsVerifier::new("example.com", ORIGIN, Secret::new(vec![7; 8]));
    }
}
