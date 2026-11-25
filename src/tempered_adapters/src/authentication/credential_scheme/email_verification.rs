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
        let not_found = |e| match e {
            tempered_core::EmailChangeStoreError::NotFound => {
                CredentialError::InvalidVerificationToken
            }
            other => other.into(),
        };
        let hash = hash_change_token(&token);
        // Only from the account the change was asked for: a token that
        // reached someone else's session moves nothing, and is not used up.
        let (old, new) = change.store.peek(&hash).await.map_err(not_found)?;
        if old != email {
            return Err(CredentialError::InvalidVerificationToken);
        }
        // Under both addresses' credential locks: no login begins, and no
        // credential is added or removed, at either while the account moves.
        let old_lock = self.lock_credentials(&old).await?;
        let new_lock = match self.lock_credentials(&new).await {
            Ok(lock) => lock,
            Err(e) => {
                self.unlock_credentials(&old, old_lock).await;
                return Err(e);
            }
        };
        let result = self.move_account(&*change.store, &hash, &old, &new).await;
        self.unlock_credentials(&new, new_lock).await;
        self.unlock_credentials(&old, old_lock).await;
        result?;
        Ok(new)
    }
}

#[allow(private_bounds)]
impl<U, T, F, L, R, V, E, O, K> CredentialScheme<U, T, F, L, R, EmailVerify<V, E>, O, K>
where
    U: UserStore,
    T: TokenStrategy,
    F: TwoFaChallenge + Sync,
    L: ElevationRevoke + Sync,
    R: ResetCleanup + Sync,
    V: EmailVerificationTokenStore + Clone + Send + Sync + 'static,
    E: EmailClient + Clone + Send + Sync + 'static,
    O: OAuthCleanup + Sync,
    K: PasskeyCleanup + Sync,
{
    /// The email change itself, under both locks. Ordered so that no failure
    /// leaves a live session or a credential under an address with no
    /// account: whoever registers a freed address must inherit nothing.
    async fn move_account(
        &self,
        store: &dyn tempered_core::EmailChangeStore,
        hash: &[u8; 32],
        old: &Email,
        new: &Email,
    ) -> Result<(), CredentialError<T::Error>> {
        let not_found = |e| match e {
            tempered_core::EmailChangeStoreError::NotFound => {
                CredentialError::InvalidVerificationToken
            }
            other => other.into(),
        };
        // Spent here, under the lock: of two concurrent confirms one moves.
        store.consume(hash).await.map_err(not_found)?;
        // Every session and token names the old address, so they end first,
        // with pending codes and reset links: if anything below fails, the
        // old address holds no live session.
        self.two_fa.cancel_pending(old).await?;
        self.revoke_all_tokens(old).await?;
        // Atomic with the check that `new` is free. Until this succeeds
        // nothing has moved.
        self.user_store.change_email(old, new).await?;
        if let Err(e) = self.move_credentials(old, new).await {
            // Put the account back where its credentials are, so neither
            // address is left with credentials and no account.
            tracing::error!(error = %e, "email change failed part-way; moving the account back");
            self.roll_back_move(old, new).await;
            return Err(e);
        }
        Ok(())
    }

    /// Move everything durable keyed by the address, and the proof of it.
    /// Each step moves whatever is still at `from`, so running it again (or
    /// the other way) finishes or undoes a partial move.
    async fn move_credentials(
        &self,
        from: &Email,
        to: &Email,
    ) -> Result<(), CredentialError<T::Error>> {
        // Passkeys belong to the account id and stay; enrolments started
        // under the old address go (they are filed by it).
        self.passkeys.drop_ceremonies(from).await?;
        // The new address just proved itself; the old one's mark goes.
        self.email_verify.mark_verified(to).await?;
        self.email_verify.forget(from).await?;
        Ok(())
    }

    /// Undo a partial move, best effort: each credential store back to
    /// `old` (every one is tried, whichever fail), then the account. What
    /// cannot be undone is logged for repair; nothing it leaves behind has a
    /// live session, which ended before the move.
    async fn roll_back_move(&self, old: &Email, new: &Email) {
        let mut failed = Vec::new();
        // The old address was proven before the change; the new one was not.
        if let Err(e) = self.email_verify.mark_verified(old).await {
            failed.push(("old address's proof", e.to_string()));
        }
        if let Err(e) = self.email_verify.forget(new).await {
            failed.push(("new address's proof", e.to_string()));
        }
        if let Err(e) = self.user_store.change_email(new, old).await {
            failed.push(("account", format!("{e:?}")));
        }
        if let Err(e) = self.revoke_all_tokens(new).await {
            failed.push(("tokens for the new address", e.to_string()));
        }
        for (what, error) in &failed {
            tracing::error!(
                what,
                error,
                "email change rollback incomplete: repair by moving these records to the account's address"
            );
        }
    }
}
