//! Email verification (the email-verification slot).

use super::*;

// ============================================================================
// Email Verification (gated on the `EmailVerify` slot)
// ============================================================================

#[async_trait]
impl<U, T, F, L, R, V, E, O, K> RequiresEmailVerification
    for CredentialScheme<U, T, F, L, R, EmailVerify<V, E>, O, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    V: EmailVerificationTokenStore + Clone + Send + Sync + 'static,
    E: EmailClient + Clone + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    K: Clone + Send + Sync + 'static,
{
    type EmailVerificationError = CredentialError<T::Error>;

    #[tracing::instrument(name = "CredentialScheme::initiate_email_verification", skip(self))]
    async fn initiate_email_verification(
        &self,
        email: Email,
    ) -> Result<(), Self::EmailVerificationError> {
        // Nothing is sent for an address that is already verified.
        Ok(self.email_verify.send_verification(&email).await?)
    }

    #[tracing::instrument(name = "CredentialScheme::verify_email", skip(self, token))]
    async fn verify_email(
        &self,
        email: &Email,
        token: String,
    ) -> Result<(), Self::EmailVerificationError> {
        let token = EmailVerificationToken::parse(&token)
            .ok_or(CredentialError::InvalidVerificationToken)?;

        let sent_to = self
            .email_verify
            .store
            .consume_token(&token)
            .await
            .map_err(|_| CredentialError::InvalidVerificationToken)?;
        // Answered exactly like an unknown token: the caller learns nothing
        // about whose token it was.
        if &sent_to != email {
            return Err(CredentialError::InvalidVerificationToken);
        }

        self.email_verify.store.mark_verified(email).await?;
        Ok(())
    }

    #[tracing::instrument(name = "CredentialScheme::is_email_verified", skip(self))]
    async fn is_email_verified(&self, email: &Email) -> Result<bool, Self::EmailVerificationError> {
        Ok(self.email_verify.store.is_verified(email).await?)
    }
}
