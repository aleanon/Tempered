//! Passkeys / WebAuthn (the passkey slot).

use super::*;

// ============================================================================
// Passkeys / WebAuthn (gated on the `Passkeys` slot)
// ============================================================================

#[async_trait]
impl<U, T, F, L, R, M, O, CS, ChS, V> SupportsPasskeys
    for CredentialScheme<U, T, F, L, R, M, O, Passkeys<CS, ChS, V>>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    CS: PasskeyCredentialStore + Clone + Send + Sync + 'static,
    ChS: ChallengeStore + Clone + Send + Sync + 'static,
    V: WebAuthnVerifier + Clone + Send + Sync + 'static,
{
    type PasskeyError = CredentialError<T::Error>;

    #[tracing::instrument(name = "CredentialScheme::start_passkey_registration", skip(self))]
    async fn start_passkey_registration(
        &self,
        email: Email,
    ) -> Result<PasskeyCeremony, Self::PasskeyError> {
        Ok(self.passkeys.flow.start_registration(email).await?)
    }

    #[tracing::instrument(
        name = "CredentialScheme::finish_passkey_registration",
        skip(self, response)
    )]
    async fn finish_passkey_registration(
        &self,
        email: Email,
        ceremony_id: CeremonyId,
        response: serde_json::Value,
    ) -> Result<(), Self::PasskeyError> {
        // Storing a credential and removing a user's credentials exclude each
        // other. The session that authorised this request may have been
        // revoked since the middleware checked it; if so, the same cleanup
        // dropped the ceremony, and the flow finds none under the lock.
        let lock = self.lock_credentials(&email).await?;
        let result = self
            .passkeys
            .flow
            .finish_registration(&email, ceremony_id, response)
            .await;
        self.unlock_credentials(&email, lock).await;
        result?;
        Ok(())
    }

    #[tracing::instrument(name = "CredentialScheme::start_passkey_authentication", skip(self))]
    async fn start_passkey_authentication(
        &self,
        email: Option<Email>,
    ) -> Result<PasskeyCeremony, Self::PasskeyError> {
        Ok(self.passkeys.flow.start_authentication(email).await?)
    }

    #[tracing::instrument(
        name = "CredentialScheme::finish_passkey_authentication",
        skip(self, response)
    )]
    async fn finish_passkey_authentication(
        &self,
        ceremony_id: CeremonyId,
        response: serde_json::Value,
    ) -> Result<LoginOutcome<Self::Token>, Self::PasskeyError> {
        let (email, credential_id) = self
            .passkeys
            .flow
            .finish_authentication_with_credential(ceremony_id, response)
            .await?;
        // Only the credential says whose login this is, so the login opens
        // here and the credential is confirmed again after it: removed in
        // between, it fails; removed later, the ticket catches it.
        let ticket = self
            .tokens
            .begin(&email)
            .await
            .map_err(CredentialError::Token)?;
        self.passkeys
            .flow
            .confirm_enrolled(&email, &credential_id)
            .await?;
        // A passkey outlives nothing: if the account it was enrolled for is gone
        // (deleted since enrollment), the credential must not mint a session.
        let user = self.user_store.get_user(&email).await?;
        if self.passkeys.requires_2fa && user.requires_2fa() {
            let attempt_id = self
                .two_fa
                .issue_challenge(&email, ChallengePurpose::SignIn)
                .await?;
            return Ok(LoginOutcome::Requires2Fa { email, attempt_id });
        }
        Ok(LoginOutcome::Success(
            self.tokens
                .issue(&email, ticket)
                .await
                .map_err(CredentialError::Token)?,
        ))
    }

    async fn passkeys(
        &self,
        email: &Email,
    ) -> Result<Vec<tempered_core::PasskeySummary>, Self::PasskeyError> {
        Ok(self
            .passkeys
            .flow
            .list(email)
            .await?
            .into_iter()
            .map(|c| tempered_core::PasskeySummary {
                id: c.credential_id.0,
                name: c.name,
            })
            .collect())
    }

    async fn rename_passkey(
        &self,
        email: &Email,
        id: &tempered_core::CredentialId,
        name: Option<String>,
    ) -> Result<bool, Self::PasskeyError> {
        Ok(self.passkeys.flow.rename(email, id, name).await?)
    }

    async fn delete_passkey(
        &self,
        email: &Email,
        id: &tempered_core::CredentialId,
    ) -> Result<bool, Self::PasskeyError> {
        Ok(self.passkeys.flow.remove(email, id).await?)
    }
}
