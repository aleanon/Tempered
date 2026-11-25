//! Password reset (the password-reset slot).

use super::*;

// ============================================================================
// Password Reset (gated on the `PasswordReset` slot)
// ============================================================================

#[async_trait]
impl<U, T, F, L, P, E, M, O, K> SupportsPasswordReset
    for CredentialScheme<U, T, F, L, PasswordReset<P, E>, M, O, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: ElevationRevoke + Clone + Send + Sync + 'static,
    P: PasswordResetTokenStore + Clone + Send + Sync + 'static,
    E: EmailClient + Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    K: Clone + Send + Sync + 'static,
{
    type PasswordResetError = CredentialError<T::Error>;

    #[tracing::instrument(name = "CredentialScheme::initiate_password_reset", skip(self))]
    async fn initiate_password_reset(&self, email: Email) -> Result<(), Self::PasswordResetError> {
        // Everything that depends on whether the account exists happens
        // after the response, so neither the answer nor its timing says
        // which addresses are registered (see `deferred`). Failures are
        // logged; the caller would not have been told either way.
        let users = self.user_store.clone();
        let reset = self.password_reset.clone();
        self.password_reset
            .deferred
            .run("password reset mail", async move {
                match users.get_user(&email).await {
                    Ok(_) => {}
                    Err(UserStoreError::UserNotFound) => return,
                    Err(e) => {
                        tracing::error!(error = ?e, "password reset: user lookup failed");
                        return;
                    }
                }
                let token = PasswordResetToken::new();
                if let Err(e) = reset.store.store_token(token.clone(), email.clone()).await {
                    tracing::error!(error = ?e, "password reset: failed to store the token");
                    return;
                }
                if let Err(e) = reset
                    .email
                    .send_mail(
                        &email,
                        tempered_core::Mail::PasswordReset {
                            token: token.to_string(),
                        },
                    )
                    .await
                {
                    tracing::error!(error = e, "password reset: failed to send the mail");
                }
            });
        Ok(())
    }

    #[tracing::instrument(
        name = "CredentialScheme::complete_password_reset",
        skip(self, new_password, reset_token)
    )]
    async fn complete_password_reset(
        &self,
        reset_token: String,
        new_password: Password,
    ) -> Result<(), Self::PasswordResetError> {
        let token =
            PasswordResetToken::parse(&reset_token).ok_or(CredentialError::InvalidResetToken)?;

        // Check the new password before spending the link, so a refused one
        // can be retried with the same link. Peeking is only for that: the
        // redeem below is the check that counts.
        if self.password_policy.is_some()
            && let Ok(owner) = self.password_reset.store.get_email_for_token(&token).await
        {
            self.check_new_password(&owner, &new_password).await?;
        }

        // Atomically redeem the token before touching the password: two
        // concurrent requests can't both pass a check-then-delete, and if the
        // password update fails the token is burned (the user re-initiates)
        // rather than left valid after a successful change.
        let email = self
            .password_reset
            .store
            .consume_token(&token)
            .await
            .map_err(|e| match e {
                PasswordResetTokenStoreError::TokenNotFound => CredentialError::InvalidResetToken,
                // An outage is not a bad link: report it (as a 500) rather
                // than tell the user their link is invalid.
                e => CredentialError::PasswordResetTokenStoreError(e),
            })?;

        self.user_store
            .set_new_password(&email, new_password)
            .await?;

        // A reset is a password change — typically *because* the account may
        // be compromised — so strand every outstanding session.
        self.two_fa.cancel_pending(&email).await?;
        self.revoke_all_tokens(&email).await?;

        Ok(())
    }
}
