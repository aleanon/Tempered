//! OAuth2 / OIDC login and linking (the OAuth slot).

use super::*;

// ============================================================================
// OAuth2 / OIDC (gated on the `OAuth` slot)
// ============================================================================

#[async_trait]
impl<U, T, F, L, R, M, ST, ID, HC, K> SupportsOAuth2
    for CredentialScheme<U, T, F, L, R, M, OAuth<ST, ID, HC>, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: ElevationRevoke + Clone + Send + Sync + 'static,
    R: ResetCleanup + Clone + Send + Sync + 'static,
    M: EmailProof + Clone + Send + Sync + 'static,
    ST: OAuthStateStore + Clone + Send + Sync + 'static,
    ID: OAuthIdentityStore + Clone + Send + Sync + 'static,
    HC: OAuthHttpClient + Clone + Send + Sync + 'static,
    K: PasskeyCleanup + Clone + Send + Sync + 'static,
{
    type OAuth2Error = CredentialError<T::Error>;

    #[tracing::instrument(name = "CredentialScheme::begin_oauth", skip(self))]
    async fn begin_oauth(&self, provider: &str) -> Result<AuthorizationRequest, Self::OAuth2Error> {
        Ok(self.oauth.flow.begin(provider).await?)
    }

    #[tracing::instrument(name = "CredentialScheme::complete_oauth", skip(self, code))]
    async fn complete_oauth(
        &self,
        provider: &str,
        code: &str,
        query_state: &str,
        cookie_state: &str,
    ) -> Result<LoginOutcome<Self::Token>, Self::OAuth2Error> {
        // The flow proves who is at the provider; nothing is linked yet.
        let identity = self
            .oauth
            .flow
            .complete(provider, code, query_state, cookie_state, &self.user_store)
            .await?;
        let email = identity.email().clone();

        // From here it is an ordinary login to that email's account, creating
        // the account first if this is the user's first visit.
        if !identity.already_linked() {
            self.prepare_account_for_first_link(&email).await?;
            // Linked last: if anything above failed, the next attempt starts
            // from an unlinked identity and secures the account again.
            self.oauth.flow.link(&identity, &self.user_store).await?;
        }

        // The login opens once the account is in its final state (securing it
        // revokes its sessions, which would void an earlier ticket), and
        // before the account is read: a deletion from here on is caught.
        let ticket = self
            .tokens
            .begin(&email)
            .await
            .map_err(CredentialError::Token)?;
        // When the provider vouches for the address (it reported this one,
        // verified), the account now counts as proven. It does not once the
        // user changed their address at the provider: the identity still
        // logs in, but proves nothing about the old address. Under the
        // credential lock, so a deletion cannot clear the mark between the
        // link check and the write and leave it behind for the next account
        // at this address.
        let lock = self.lock_credentials(&email).await?;
        let marked: Result<(), CredentialError<T::Error>> = async {
            if !self
                .oauth
                .flow
                .is_linked(&identity, &self.user_store)
                .await?
            {
                // Unlinked since it was verified: the account was deleted.
                return Err(UserStoreError::UserNotFound.into());
            }
            if identity.vouches_for_email() {
                self.email_verify.mark_verified(&email).await?;
            }
            Ok(())
        }
        .await;
        self.unlock_credentials(&email, lock).await;
        marked?;
        let requires_2fa = self.user_store.get_user(&email).await?.requires_2fa;

        if requires_2fa {
            // The provider stands in for the password, not for the second
            // factor. Same path as password login: issue + deliver the
            // challenge, or error if the scheme was built without 2FA.
            let attempt_id = self
                .two_fa
                .issue_challenge(&self.subject_for(&email).await?, ChallengePurpose::SignIn)
                .await?;
            return Ok(LoginOutcome::Requires2Fa { email, attempt_id });
        }

        let token = self
            .tokens
            .issue(&self.subject_for(&email).await?, ticket)
            .await
            .map_err(CredentialError::Token)?;
        Ok(LoginOutcome::Success(token))
    }

    async fn begin_oauth_link(
        &self,
        provider: &str,
        email: Email,
    ) -> Result<AuthorizationRequest, Self::OAuth2Error> {
        Ok(self.oauth.flow.begin_link(provider, email).await?)
    }

    async fn complete_oauth_link(
        &self,
        provider: &str,
        code: &str,
        query_state: &str,
        cookie_state: &str,
    ) -> Result<Email, Self::OAuth2Error> {
        let identity = self
            .oauth
            .flow
            .complete_link(provider, code, query_state, cookie_state, &self.user_store)
            .await?;
        let account = identity.email().clone();
        // Under the credential lock, like every new way in: an account
        // deletion either finishes first (and the account is gone) or waits
        // and removes the link with the rest.
        let lock = self.lock_credentials(&account).await?;
        let result: Result<(), CredentialError<T::Error>> = async {
            self.user_store.get_user(&account).await?;
            // A linked identity counts as proof of the account's address (a
            // later first login through another provider trusts the account
            // as it is). So a provider that does not vouch for this address
            // may be linked only to an account whose address is already
            // proven; otherwise whoever squatted on the address could link
            // their own provider and make the account look proven.
            if !identity.vouches_for_email() {
                let proven = self.email_verify.proof(&account).await? == AddressProof::Verified
                    || self
                        .oauth
                        .flow
                        .has_linked_identity(&account, &self.user_store)
                        .await?;
                if !proven {
                    return Err(CredentialError::AddressNotProven);
                }
            }
            self.oauth.flow.link(&identity, &self.user_store).await?;
            if identity.vouches_for_email() {
                self.email_verify.mark_verified(&account).await?;
            }
            Ok(())
        }
        .await;
        self.unlock_credentials(&account, lock).await;
        result?;
        Ok(account)
    }

    async fn oauth_links(&self, email: &Email) -> Result<Vec<String>, Self::OAuth2Error> {
        let user = match self.subject_for(email).await {
            Ok(user) => user.id,
            // No account, no links.
            Err(UserStoreError::UserNotFound) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        Ok(self.oauth.flow.links(&user).await?)
    }

    async fn unlink_oauth(&self, email: &Email, provider: &str) -> Result<bool, Self::OAuth2Error> {
        let user = match self.subject_for(email).await {
            Ok(user) => user.id,
            Err(UserStoreError::UserNotFound) => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        Ok(self.oauth.flow.unlink(&user, provider).await?)
    }
}

// Private helpers: the slot traits in the bounds are internal by design.
#[allow(private_bounds)]
impl<U, T, F, L, R, M, ST, ID, HC, K> CredentialScheme<U, T, F, L, R, M, OAuth<ST, ID, HC>, K>
where
    U: UserStore,
    T: TokenStrategy,
    M: EmailProof + Send + Sync,
    ST: OAuthStateStore + Send + Sync,
    ID: OAuthIdentityStore + Send + Sync,
    HC: OAuthHttpClient + Send + Sync,
    K: PasskeyCleanup + Send + Sync,
    F: TwoFaChallenge + Send + Sync,
    L: ElevationRevoke + Send + Sync,
    R: ResetCleanup + Send + Sync,
{
    /// Get `email`'s account ready for the first login through a provider
    /// identity that is not linked to it yet.
    ///
    /// - No account: create one. The user store requires a password, so it gets
    ///   a random one nobody knows; the user signs in through the provider and
    ///   can set a real password through password reset.
    /// - An account whose address is already proven: left untouched.
    /// - An account whose address was never proven: secured first, see
    ///   [`secure_unproven_account`](Self::secure_unproven_account).
    async fn prepare_account_for_first_link(
        &self,
        email: &Email,
    ) -> Result<(), CredentialError<T::Error>> {
        match self.user_store.get_user(email).await {
            Ok(_) => {}
            Err(UserStoreError::UserNotFound) => {
                let user = User::new(email.clone(), unknowable_password(), false);
                match self.user_store.add_user(user).await {
                    Ok(()) => return Ok(()),
                    // Lost a race with a signup for the same address. That
                    // account is as unproven as any other: fall through.
                    Err(UserStoreError::UserAlreadyExists) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) => return Err(e.into()),
        }

        let proof = self.email_verify.proof(email).await?;
        let proven = proof == AddressProof::Verified
            || self
                .oauth
                .flow
                .has_linked_identity(email, &self.user_store)
                .await?;
        if proven {
            return Ok(());
        }

        // The 2FA requirement is dropped only when the scheme positively knows
        // the address was never confirmed. Without email verification every
        // signup account looks unproven, and most of them are genuine: their
        // owners keep the second factor they chose.
        let drop_two_fa = proof == AddressProof::Unverified;
        self.secure_unproven_account(email, drop_two_fa).await
    }
}

/// A password no one can know or guess: 32 random bytes, base64url-encoded.
fn unknowable_password() -> Password {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand::RngCore;

    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    Password::try_from(Secret::new(URL_SAFE_NO_PAD.encode(buf)))
        .expect("a 43-character password satisfies the length rule")
}

impl<U, T, F, L, R, M, ST, ID, HC, K> HttpOAuth2Scheme
    for CredentialScheme<U, T, F, L, R, M, OAuth<ST, ID, HC>, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    L: ElevatedCookieName + ElevationRevoke + Clone + Send + Sync + 'static,
    R: ResetCleanup + Clone + Send + Sync + 'static,
    M: EmailProof + Clone + Send + Sync + 'static,
    ST: OAuthStateStore + Clone + Send + Sync + 'static,
    ID: OAuthIdentityStore + Clone + Send + Sync + 'static,
    HC: OAuthHttpClient + Clone + Send + Sync + 'static,
    K: PasskeyCleanup + Clone + Send + Sync + 'static,
{
    fn oauth_state_cookie_name(&self) -> &str {
        &self.oauth.state_cookie_name
    }

    fn oauth_link_redirect(&self) -> &str {
        &self.oauth.post_login_redirect
    }

    fn create_oauth_start_response<RB: ResponseBuilder>(
        &self,
        builder: RB,
        authorization: AuthorizationRequest,
    ) -> Result<RB::Response, tempered_core::ResponseBuilderError> {
        // Max-Age bounds how long the CSRF state cookie lingers if the user
        // abandons the flow; 10 minutes is ample to complete a provider redirect.
        let state_cookie = format!(
            "{}={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600",
            self.oauth.state_cookie_name, authorization.state
        );

        builder
            .status(302)
            .cookie(&state_cookie)
            .header("location", &authorization.authorize_url)
            .build()
    }

    fn create_oauth_callback_response<RB: ResponseBuilder>(
        &self,
        builder: RB,
        outcome: LoginOutcome<Self::Token>,
    ) -> Result<RB::Response, tempered_core::ResponseBuilderError> {
        // Either way the state cookie is spent.
        let clear_state = crate::cookie_util::expired_cookie(&self.oauth.state_cookie_name);
        let builder = builder.status(302).cookie(&clear_state);

        match outcome {
            // Deliver the issued token exactly as login does and enter the app.
            LoginOutcome::Success(token) => {
                let mut builder = builder.cookie(&self.tokens.auth_cookie(&token));
                for cookie in self.tokens.extra_login_cookies(&token) {
                    builder = builder.cookie(&cookie);
                }
                builder
                    .header("location", &self.oauth.post_login_redirect)
                    .build()
            }
            // No token yet: send the browser to the app's second-factor step.
            // What it needs to call the 2FA verification route travels in a
            // short-lived cookie, not the URL (see `oauth_two_fa_redirect`).
            LoginOutcome::Requires2Fa { email, attempt_id } => builder
                .cookie(&two_fa_handoff_cookie(&email, &attempt_id))
                .header("location", &with_two_fa_marker(&self.oauth.two_fa_redirect))
                .build(),
        }
    }
}

/// The OAuth state cookie's default name. The `__Host-` prefix makes the
/// browser refuse the cookie unless it is `Secure`, has `Path=/` and no
/// `Domain`, so only this exact host can set it: a sibling subdomain cannot
/// plant a state of its own (cookie tossing) and so cannot complete its own
/// provider login in the victim's browser.
pub const DEFAULT_OAUTH_STATE_COOKIE: &str = "__Host-oauth_state";

/// Name of the cookie that hands a pending OAuth 2FA login to the page. The
/// `__Host-` prefix keeps a sibling subdomain from planting a hand-off of its
/// own, as for [`DEFAULT_OAUTH_STATE_COOKIE`].
pub const OAUTH_TWO_FA_COOKIE: &str = "__Host-oauth_2fa";

/// The hand-off cookie: `loginAttemptId` and `email` as a query string.
///
/// Deliberately not `HttpOnly`: the page's script must read it to call the 2FA
/// verification route, exactly as it reads the attempt id from the JSON body
/// after a password login. Neither value is a credential — the attempt id is
/// useless without the emailed code. `Max-Age` matches the OAuth state cookie.
fn two_fa_handoff_cookie(email: &Email, attempt_id: &TwoFaAttemptId) -> String {
    let value = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("loginAttemptId", &attempt_id.to_string())
        .append_pair("email", email.as_ref().expose_secret())
        .finish();
    format!("{OAUTH_TWO_FA_COOKIE}={value}; Secure; SameSite=Lax; Path=/; Max-Age=600")
}

/// `base` with `oauth_2fa=required` added to its query string, keeping any
/// query or fragment `base` already has.
fn with_two_fa_marker(base: &str) -> String {
    let (path_and_query, fragment) = match base.split_once('#') {
        Some((before, after)) => (before, Some(after)),
        None => (base, None),
    };
    let separator = if path_and_query.contains('?') {
        '&'
    } else {
        '?'
    };
    let mut location = format!("{path_and_query}{separator}oauth_2fa=required");
    if let Some(fragment) = fragment {
        location.push('#');
        location.push_str(fragment);
    }
    location
}

// Securing an account is shared by the paths that prove its address after
// the fact: a provider login (above) and an email login.
#[allow(private_bounds)]
impl<U, T, F, L, R, M, O, K> CredentialScheme<U, T, F, L, R, M, O, K>
where
    U: UserStore,
    T: TokenStrategy,
    F: TwoFaChallenge + Send + Sync,
    L: ElevationRevoke + Send + Sync,
    R: ResetCleanup + Send + Sync,
    M: Send + Sync,
    O: Send + Sync,
    K: PasskeyCleanup + Send + Sync,
{
    /// Remove every way into an account that predates proof of its address.
    ///
    /// Signup does not prove the address belongs to whoever signed up, so an
    /// attacker can register a victim's address and wait for the victim to
    /// arrive through a provider or an email login ("account pre-hijacking"). Whoever created
    /// this account may still hold its password, a session, or a passkey: all
    /// three go before the provider's user is let in. A genuine user who
    /// signed up with a password loses it and sets a new one via password
    /// reset.
    ///
    /// With `drop_two_fa`, the account's 2FA requirement goes too: it was
    /// chosen by whoever signed up, and the owner should not be held to a
    /// second factor they did not set up (or cannot pass).
    ///
    /// It all happens under the user's credential lock, so one credential
    /// cannot mint another while this runs: no login begins, and a session
    /// that is about to be revoked cannot enrol a passkey (enrolment takes the
    /// same lock, and enrolments already started are dropped with the
    /// passkeys). The order and the second passkey pass are what remains if
    /// the lock expires under a stalled store: password first (no new password
    /// logins), then passkeys, then sessions, then passkeys once more.
    pub(super) async fn secure_unproven_account(
        &self,
        email: &Email,
        drop_two_fa: bool,
    ) -> Result<(), CredentialError<T::Error>> {
        let lock = self.lock_credentials(email).await?;
        let result: Result<(), CredentialError<T::Error>> = async {
            let account = self.subject_for(email).await?;
            let id = account.id;
            self.user_store
                .set_new_password(email, unknowable_password())
                .await?;
            if drop_two_fa {
                self.user_store.set_requires_2fa(email, false).await?;
            }
            self.passkeys.forget_user(&account).await?;
            // An authenticator app is a second factor whoever signed up
            // chose. With 2FA kept on, codes go to the address the provider
            // has just vouched for.
            self.two_fa.forget_user(&id).await?;
            // So are API keys whoever signed up issued themselves.
            self.forget_api_keys(&id).await?;
            self.two_fa.cancel_pending(email).await?;
            self.revoke_all_tokens(email).await?;
            // Once more, in case the lock expired under a slow store and an
            // enrolment authorised before the revocation slipped in.
            self.passkeys.forget_user(&account).await?;
            self.two_fa.forget_user(&id).await?;
            Ok(())
        }
        .await;
        self.unlock_credentials(email, lock).await;
        result
    }
}
