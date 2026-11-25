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
        let user = self.subject_for(&email).await?;
        Ok(self.passkeys.flow.start_registration(user).await?)
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
        // And the account must still be there (deleted, or moved to another
        // address): a passkey under a free address would be inherited by
        // whoever registers it next.
        let result = match self.subject_for(&email).await {
            Ok(user) => self
                .passkeys
                .flow
                .finish_registration(&user, ceremony_id, response)
                .await
                .map_err(CredentialError::from),
            Err(e) => Err(e.into()),
        };
        self.unlock_credentials(&email, lock).await;
        result?;
        Ok(())
    }

    #[tracing::instrument(name = "CredentialScheme::start_passkey_authentication", skip(self))]
    async fn start_passkey_authentication(
        &self,
        email: Option<Email>,
    ) -> Result<PasskeyCeremony, Self::PasskeyError> {
        let user = match email {
            None => None,
            Some(email) => match self.subject_for(&email).await {
                Ok(user) => Some(user),
                // No such account: a ceremony that no credential answers,
                // so the answer does not tell the two apart.
                Err(UserStoreError::UserNotFound) => Some(tempered_core::Subject {
                    id: tempered_core::UserId::new(),
                    email,
                }),
                Err(e) => return Err(e.into()),
            },
        };
        Ok(self.passkeys.flow.start_authentication(user).await?)
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
        let (owner, credential_id) = self
            .passkeys
            .flow
            .finish_authentication_with_credential(ceremony_id, response)
            .await?;
        // The credential names the account by id; the login is for it at
        // whatever address it has now. A passkey outlives nothing: if the
        // account is gone, the credential must not mint a session.
        let user = self.user_store.get_user_by_id(&owner).await?;
        let subject = tempered_core::Subject::from(&user);
        let email = subject.email.clone();
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
            .confirm_enrolled(&owner, &credential_id)
            .await?;
        // The ticket is for the address read above. If the account moved
        // since, its old address may be anyone's soon: refuse, rather than
        // mint a token naming it. A move from here on revokes the ticket.
        let user = self.user_store.get_user_by_id(&owner).await?;
        if user.email != email {
            return Err(CredentialError::AccountBusy);
        }
        if self.passkeys.requires_2fa && user.requires_2fa() {
            let attempt_id = self
                .two_fa
                .issue_challenge(&subject, ChallengePurpose::SignIn)
                .await?;
            return Ok(LoginOutcome::Requires2Fa { email, attempt_id });
        }
        Ok(LoginOutcome::Success(
            self.tokens
                .issue(&subject, ticket)
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
            .list(&match self.subject_for(email).await {
                Ok(user) => user.id,
                // No account, no passkeys.
                Err(UserStoreError::UserNotFound) => return Ok(Vec::new()),
                Err(e) => return Err(e.into()),
            })
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
        let user = match self.subject_for(email).await {
            Ok(user) => user.id,
            Err(UserStoreError::UserNotFound) => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        Ok(self.passkeys.flow.rename(&user, id, name).await?)
    }

    async fn delete_passkey(
        &self,
        email: &Email,
        id: &tempered_core::CredentialId,
    ) -> Result<bool, Self::PasskeyError> {
        let user = match self.subject_for(email).await {
            Ok(user) => user.id,
            Err(UserStoreError::UserNotFound) => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        Ok(self.passkeys.flow.remove(&user, id).await?)
    }
}
