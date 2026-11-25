//! Two-factor authentication, passwordless email login and TOTP (the 2FA slot).

use super::*;

// ============================================================================
// Two-Factor Authentication (gated on the `TwoFa` slot)
// ============================================================================

#[async_trait]
impl<U, T, S, E, P, L, R, M, O, K> SupportsTwoFactor
    for CredentialScheme<U, T, TwoFa<S, E, P>, L, R, M, O, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    S: TwoFaCodeStore + Clone + Send + Sync + 'static,
    E: EmailClient + Clone + Send + Sync + 'static,
    P: TotpFactor + Clone + 'static,
    L: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    K: Clone + Send + Sync + 'static,
{
    type TwoFactorError = CredentialError<T::Error>;

    #[tracing::instrument(name = "CredentialScheme::verify_2fa", skip(self, code))]
    async fn verify_2fa(
        &self,
        email: Email,
        attempt_id: TwoFaAttemptId,
        code: TwoFaCode,
    ) -> Result<Self::Token, Self::TwoFactorError> {
        let ticket = self
            .tokens
            .begin(&email)
            .await
            .map_err(CredentialError::Token)?;
        // Checks and consumes the code in one step: two concurrent requests
        // with the right code cannot both get past it.
        self.two_fa.redeem(&email, &attempt_id, &code).await?;
        // The account may have been deleted since the first factor.
        self.user_store.get_user(&email).await?;
        Ok(self
            .tokens
            .issue(&email, ticket)
            .await
            .map_err(CredentialError::Token)?)
    }
}

// ============================================================================
// Passwordless login by email (on the 2FA slot)
// ============================================================================

#[async_trait]
impl<U, T, S, E, P, L, R, M, O, K> tempered_core::SupportsEmailLogin
    for CredentialScheme<U, T, TwoFa<S, E, P>, L, R, M, O, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    S: TwoFaCodeStore + Clone + Send + Sync + 'static,
    E: EmailClient + Clone + Send + Sync + 'static,
    P: TotpFactor + Clone + 'static,
    L: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    K: Clone + Send + Sync + 'static,
{
    type EmailLoginError = CredentialError<T::Error>;

    async fn start_email_login(
        &self,
        email: Email,
    ) -> Result<TwoFaAttemptId, Self::EmailLoginError> {
        let Some(settings) = &self.two_fa.email_login else {
            return Err(CredentialError::TwoFaNotConfigured);
        };
        // The attempt id is the answer whether or not the account exists;
        // the rest happens after the response (see `deferred`).
        let attempt_id = TwoFaAttemptId::new();
        let (users, store, mail) = (
            self.user_store.clone(),
            settings.store.clone(),
            self.two_fa.email.clone(),
        );
        let link_base = settings.link_base.clone();
        let attempt = attempt_id.clone();
        settings.deferred.run("email login mail", async move {
            match users.get_user(&email).await {
                Ok(_) => {}
                Err(UserStoreError::UserNotFound) => return,
                Err(e) => {
                    tracing::error!(error = ?e, "email login: user lookup failed");
                    return;
                }
            }
            let code = TwoFaCode::new();
            if let Err(e) = store
                .store_code(email.clone(), attempt.clone(), code.clone())
                .await
            {
                tracing::error!(error = ?e, "email login: failed to store the code");
                return;
            }
            let link = match &link_base {
                None => None,
                Some(page) => {
                    let mut url = match url::Url::parse(page) {
                        Ok(url) => url,
                        Err(e) => {
                            tracing::error!(error = %e, "email login: the link page is not a URL");
                            return;
                        }
                    };
                    url.query_pairs_mut()
                        .append_pair("email", email.as_ref().expose_secret())
                        .append_pair("loginAttemptId", &attempt.to_string())
                        .append_pair("code", code.as_str());
                    Some(url.to_string())
                }
            };
            let message = tempered_core::Mail::EmailLogin { code, link };
            if let Err(e) = mail.send_mail(&email, message).await {
                tracing::error!(error = e, "email login: failed to send the mail");
            }
        });
        Ok(attempt_id)
    }

    async fn finish_email_login(
        &self,
        email: Email,
        attempt_id: TwoFaAttemptId,
        code: TwoFaCode,
    ) -> Result<LoginOutcome<Self::Token>, Self::EmailLoginError> {
        let Some(settings) = &self.two_fa.email_login else {
            return Err(CredentialError::TwoFaNotConfigured);
        };
        // Taken before the code is checked, like a password login's.
        let ticket = self
            .tokens
            .begin(&email)
            .await
            .map_err(CredentialError::Token)?;
        // A code from the email-login store: it proves the inbox, nothing
        // more, and is not redeemable as a second factor anywhere.
        settings
            .store
            .redeem_code(&email, &attempt_id, &code)
            .await?;
        let user = self.user_store.get_user(&email).await?;
        if user.requires_2fa() {
            // The inbox is one factor, and a 2FA account needs a second one
            // that is not the inbox again: its authenticator app. Without
            // one, its factors are the password and the inbox, and this
            // login cannot stand in for the password.
            let has_app = self
                .two_fa
                .totp
                .uses_totp(&email)
                .await
                .map_err(TwoFaChallengeError::from)?;
            if !has_app {
                return Err(CredentialError::EmailLoginNotAllowed);
            }
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
}

// ============================================================================
// TOTP (on the 2FA slot; needs elevation for its routes)
// ============================================================================

impl<U, T, S, E, TE, R, M, O, K> CredentialScheme<U, T, TwoFa<S, E>, Elevation<TE>, R, M, O, K> {
    /// Let users add an authenticator app (TOTP) as their second factor,
    /// with recovery codes, lighting up [`SupportsTotp`] and its routes
    /// (`/elevated/totp/...`, elevated tier: adding or removing a second
    /// factor needs a fresh re-authentication). `issuer` is the name the
    /// app shows next to the account. Needs [`supports_2fa`](Self::supports_2fa)
    /// and elevation first.
    ///
    /// An account with an app gets no mailed code at login: its 2FA step
    /// takes the app's code or a recovery code, in the same `2FACode` field.
    // The return type spells out every capability slot on purpose: it is the
    // typestate transition.
    #[allow(clippy::type_complexity)]
    pub fn supports_totp<TS>(
        self,
        store: TS,
        issuer: impl Into<String>,
    ) -> CredentialScheme<U, T, TwoFa<S, E, Totp<TS>>, Elevation<TE>, R, M, O, K> {
        CredentialScheme {
            user_store: self.user_store,
            tokens: self.tokens,
            two_fa: TwoFa {
                store: self.two_fa.store,
                email: self.two_fa.email,
                totp: Totp::new(store, issuer),
                email_login: self.two_fa.email_login,
            },
            elevation: self.elevation,
            password_reset: self.password_reset,
            email_verify: self.email_verify,
            oauth: self.oauth,
            passkeys: self.passkeys,
            routes: self.routes,
            rate_limit: self.rate_limit,
            password_policy: self.password_policy,
            api_keys: self.api_keys,
            events: self.events,
            deferred: self.deferred,
        }
    }
}

#[async_trait]
impl<U, T, S, E, TS, L, R, M, O, K> SupportsTotp
    for CredentialScheme<U, T, TwoFa<S, E, Totp<TS>>, L, R, M, O, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    S: TwoFaCodeStore + Clone + Send + Sync + 'static,
    E: EmailClient + Clone + Send + Sync + 'static,
    TS: TotpStore + Clone + 'static,
    L: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    K: Clone + Send + Sync + 'static,
{
    type TotpError = CredentialError<T::Error>;

    // Adding or removing a second factor and removing a user's credentials
    // (account deletion, securing an unproven account) exclude each other,
    // as passkey enrolment does. The session that authorised the request may
    // have been revoked since the middleware checked it; then the cleanup
    // also removed the pending secret, and there is nothing left to confirm.

    async fn start_totp(&self, email: Email) -> Result<TotpEnrollment, Self::TotpError> {
        let lock = self.lock_credentials(&email).await?;
        let result = self.start_totp_unlocked(email.clone()).await;
        self.unlock_credentials(&email, lock).await;
        result
    }

    async fn confirm_totp(
        &self,
        email: Email,
        code: TwoFaCode,
    ) -> Result<Vec<String>, Self::TotpError> {
        let lock = self.lock_credentials(&email).await?;
        let result = self.confirm_totp_unlocked(email.clone(), code).await;
        self.unlock_credentials(&email, lock).await;
        result
    }

    async fn disable_totp(&self, email: Email) -> Result<(), Self::TotpError> {
        let lock = self.lock_credentials(&email).await?;
        let result = self.disable_totp_unlocked(email.clone()).await;
        self.unlock_credentials(&email, lock).await;
        result
    }

    async fn regenerate_recovery_codes(
        &self,
        email: Email,
    ) -> Result<Vec<String>, Self::TotpError> {
        let lock = self.lock_credentials(&email).await?;
        let result = self.regenerate_recovery_codes_unlocked(email.clone()).await;
        self.unlock_credentials(&email, lock).await;
        result
    }
}

impl<U, T, S, E, TS, L, R, M, O, K> CredentialScheme<U, T, TwoFa<S, E, Totp<TS>>, L, R, M, O, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    S: TwoFaCodeStore + Clone + Send + Sync + 'static,
    E: EmailClient + Clone + Send + Sync + 'static,
    TS: TotpStore + Clone + 'static,
    L: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    K: Clone + Send + Sync + 'static,
{
    // The work of each `SupportsTotp` method; the trait methods run these
    // under the credential lock.

    async fn start_totp_unlocked(
        &self,
        email: Email,
    ) -> Result<TotpEnrollment, CredentialError<T::Error>> {
        let totp = &self.two_fa.totp;
        let secret = totp::new_secret();
        let enrollment = TotpEnrollment {
            secret: Secret::new(totp::base32(secret.expose_secret())),
            otpauth_uri: Secret::new(totp::otpauth_uri(
                &totp.issuer,
                &email,
                secret.expose_secret(),
            )),
        };
        totp.store.set_pending(&email, secret).await?;
        Ok(enrollment)
    }

    async fn confirm_totp_unlocked(
        &self,
        email: Email,
        code: TwoFaCode,
    ) -> Result<Vec<String>, CredentialError<T::Error>> {
        let store = &self.two_fa.totp.store;
        let Some(pending) = store.pending(&email).await? else {
            return Err(CredentialError::TotpNotEnrolled(
                "Start adding an authenticator app first",
            ));
        };
        let Some(step) = totp::matching_step(pending.expose_secret(), &code, totp::unix_now())
        else {
            return Err(TwoFaCodeStoreError::Invalid2FACode.into());
        };
        let (shown, hashes) = totp::new_recovery_codes();
        if !store.activate(&email, step, hashes).await? {
            return Err(CredentialError::TotpNotEnrolled(
                "Start adding an authenticator app first",
            ));
        }
        // The app is the second factor now, so 2FA is on.
        self.user_store.set_requires_2fa(&email, true).await?;
        Ok(shown)
    }

    async fn disable_totp_unlocked(&self, email: Email) -> Result<(), CredentialError<T::Error>> {
        Ok(self.two_fa.totp.store.delete_all_for_user(&email).await?)
    }

    async fn regenerate_recovery_codes_unlocked(
        &self,
        email: Email,
    ) -> Result<Vec<String>, CredentialError<T::Error>> {
        let store = &self.two_fa.totp.store;
        if store.active(&email).await?.is_none() {
            return Err(CredentialError::TotpNotEnrolled(
                "No authenticator app is enabled",
            ));
        }
        let (shown, hashes) = totp::new_recovery_codes();
        store.replace_recovery_codes(&email, hashes).await?;
        Ok(shown)
    }
}
