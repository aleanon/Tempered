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

// ============================================================================
// Email change (a setting on the `EmailVerify` slot)
// ============================================================================

fn hash_change_token(token: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(token.as_bytes()).into()
}

#[async_trait]
impl<U, T, F, L, R, V, E, O, K> tempered_core::SupportsEmailChange
    for CredentialScheme<U, T, F, L, R, EmailVerify<V, E>, O, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: ElevationRevoke + Clone + Send + Sync + 'static,
    R: ResetCleanup + Clone + Send + Sync + 'static,
    V: EmailVerificationTokenStore + Clone + Send + Sync + 'static,
    E: EmailClient + Clone + Send + Sync + 'static,
    O: OAuthCleanup + Clone + Send + Sync + 'static,
    K: PasskeyCleanup + Clone + Send + Sync + 'static,
{
    type EmailChangeError = CredentialError<T::Error>;

    #[tracing::instrument(name = "CredentialScheme::request_email_change", skip_all)]
    async fn request_email_change(
        &self,
        email: Email,
        new: Email,
    ) -> Result<(), Self::EmailChangeError> {
        let Some(change) = &self.email_verify.change else {
            return Err(CredentialError::EmailChangeNotConfigured);
        };
        if new == email {
            return Err(CredentialError::UserError(UserError::InvalidEmail));
        }
        // Whether `new` is taken decides what is sent, so it is decided after
        // the response, like signup.
        let (users, store, mail) = (
            self.user_store.clone(),
            change.store.clone(),
            self.email_verify.email.clone(),
        );
        self.email_verify
            .deferred
            .run("email change mail", async move {
                match users.get_user(&new).await {
                    Ok(_) => {
                        // Taken: its owner hears that someone tried, and nothing
                        // moves.
                        if let Err(e) = mail
                            .send_mail(&new, tempered_core::Mail::AlreadyRegistered)
                            .await
                        {
                            tracing::error!(
                                error = e,
                                "email change: notice to the taken address failed"
                            );
                        }
                        return;
                    }
                    Err(UserStoreError::UserNotFound) => {}
                    Err(e) => {
                        tracing::error!(error = ?e, "email change: user lookup failed");
                        return;
                    }
                }
                use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
                let mut raw = [0u8; 32];
                rand::fill(&mut raw);
                let token = URL_SAFE_NO_PAD.encode(raw);
                if let Err(e) = store
                    .create(
                        hash_change_token(&token),
                        email.clone(),
                        new.clone(),
                        EMAIL_CHANGE_TTL_SECONDS,
                    )
                    .await
                {
                    tracing::error!(error = %e, "email change: failed to store the request");
                    return;
                }
                if let Err(e) = mail
                    .send_mail(&new, tempered_core::Mail::ConfirmEmailChange { token })
                    .await
                {
                    tracing::error!(error = e, "email change: confirmation mail failed");
                }
                let notice = tempered_core::Mail::EmailChangeRequested {
                    new: new.as_ref().expose_secret().clone(),
                };
                if let Err(e) = mail.send_mail(&email, notice).await {
                    tracing::error!(error = e, "email change: notice to the old address failed");
                }
            });
        Ok(())
    }

    #[tracing::instrument(name = "CredentialScheme::confirm_email_change", skip_all)]
    async fn confirm_email_change(
        &self,
        email: Email,
        token: String,
    ) -> Result<Email, Self::EmailChangeError> {
        let Some(change) = &self.email_verify.change else {
            return Err(CredentialError::EmailChangeNotConfigured);
        };
        let (old, new) = change
            .store
            .consume(&hash_change_token(&token))
            .await
            .map_err(|e| match e {
                tempered_core::EmailChangeStoreError::NotFound => {
                    CredentialError::InvalidVerificationToken
                }
                other => other.into(),
            })?;
        // Only from the account the change was asked for: a token that
        // reached someone else's session moves nothing.
        if old != email {
            return Err(CredentialError::InvalidVerificationToken);
        }
        // Under the credential lock: no login begins, and no credential is
        // added or removed, while the account changes address.
        let lock = self.lock_credentials(&old).await?;
        let result: Result<(), CredentialError<T::Error>> = async {
            // Atomic with the check that `new` is free.
            self.user_store.change_email(&old, &new).await?;
            // Everything durable that is keyed by the address moves with it.
            self.passkeys.move_user(&old, &new).await?;
            self.oauth.move_user(&old, &new).await?;
            self.two_fa.move_user(&old, &new).await?;
            if let Some(keys) = self.api_key_store() {
                keys.reassign(&old, &new)
                    .await
                    .map_err(|e| CredentialError::ApiKeys(e.to_string()))?;
            }
            // The new address just proved itself; the old one's mark goes.
            self.email_verify.mark_verified(&new).await?;
            self.email_verify.forget(&old).await?;
            // Every session and token names the old address: they end. So do
            // pending codes and reset links.
            self.two_fa.cancel_pending(&old).await?;
            self.revoke_all_tokens(&old).await?;
            Ok(())
        }
        .await;
        self.unlock_credentials(&old, lock).await;
        result?;
        Ok(new)
    }
}
