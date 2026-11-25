//! Elevated ("sudo") tokens (the elevation slot).

use super::*;

// ============================================================================
// Elevated Tokens / "Sudo" (gated on the `Elevation` slot)
// ============================================================================

#[async_trait]
impl<U, T, F, TE, R, M, O, K> SupportsElevation
    for CredentialScheme<U, T, F, Elevation<TE>, R, M, O, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    TE: TokenStrategy,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    K: Clone + Send + Sync + 'static,
{
    type ElevatedToken = TE::Token;
    type ElevatedValidator = TE::Validator;
    type ElevationError = CredentialError<TE::Error>;

    #[tracing::instrument(name = "CredentialScheme::elevate", skip(self, password))]
    async fn elevate(
        &self,
        email: Email,
        password: Password,
    ) -> Result<LoginOutcome<Self::ElevatedToken>, Self::ElevationError> {
        // Re-authenticate, then mint a token via the *elevated* strategy.
        let ticket = self
            .elevation
            .tokens
            .begin(&email)
            .await
            .map_err(CredentialError::Token)?;
        match self.user_store.authenticate_user(&email, &password).await? {
            // The second factor guards sudo as it guards login: a password
            // alone (say, phished, plus a stolen session) must not reach the
            // elevated routes. Fails closed without the 2FA capability.
            ValidatedUser::Requires2Fa(email) => {
                let attempt_id = self
                    .two_fa
                    .issue_challenge(&email, ChallengePurpose::Elevation)
                    .await?;
                Ok(LoginOutcome::Requires2Fa { email, attempt_id })
            }
            ValidatedUser::No2Fa(email) => Ok(LoginOutcome::Success(
                self.elevation
                    .tokens
                    .issue(&self.subject_for(&email).await?, ticket)
                    .await
                    .map_err(CredentialError::Token)?,
            )),
        }
    }

    #[tracing::instrument(name = "CredentialScheme::verify_elevation_2fa", skip(self, code))]
    async fn verify_elevation_2fa(
        &self,
        email: Email,
        attempt_id: TwoFaAttemptId,
        code: TwoFaCode,
    ) -> Result<Self::ElevatedToken, Self::ElevationError> {
        let ticket = self
            .elevation
            .tokens
            .begin(&email)
            .await
            .map_err(CredentialError::Token)?;
        self.two_fa.redeem(&email, &attempt_id, &code).await?;
        // The account may have been deleted since the first factor.
        let subject = self.subject_for(&email).await?;
        Ok(self
            .elevation
            .tokens
            .issue(&subject, ticket)
            .await
            .map_err(CredentialError::Token)?)
    }

    fn elevated_validator(&self) -> &Self::ElevatedValidator {
        self.elevation.tokens.validator()
    }

    async fn revoke_elevated_token(
        &self,
        token: &Self::ElevatedToken,
    ) -> Result<(), Self::ElevationError> {
        self.elevation
            .tokens
            .revoke(token)
            .await
            .map_err(CredentialError::Token)?;
        Ok(())
    }
}

impl<U, T, F, TE, R, M, O, K> tempered_core::HttpElevationScheme
    for CredentialScheme<U, T, F, Elevation<TE>, R, M, O, K>
where
    U: UserStore + Clone + 'static,
    T: TokenStrategy,
    F: TwoFaChallenge + Clone + Send + Sync + 'static,
    TE: TokenStrategy,
    R: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    K: Clone + Send + Sync + 'static,
{
    fn create_elevation_response<RB: ResponseBuilder>(
        &self,
        builder: RB,
        outcome: LoginOutcome<Self::ElevatedToken>,
    ) -> Result<RB::Response, tempered_core::ResponseBuilderError> {
        match outcome {
            LoginOutcome::Success(elevated_token) => builder
                .status(200)
                .cookie(&self.elevation.tokens.auth_cookie(&elevated_token))
                .json_body(serde_json::json!({
                    "status": "elevated",
                    "message": "Elevation successful"
                }))
                .build(),
            // Same shape as a 2FA login: the code was sent, and
            // `/elevate/verify-2fa` takes it with this attempt id.
            LoginOutcome::Requires2Fa { attempt_id, .. } => builder
                .status(206)
                .json_body(serde_json::json!({
                    "status": "requires_2fa",
                    "message": "2FA required",
                    "loginAttemptId": attempt_id.to_string()
                }))
                .build(),
        }
    }

    fn extract_elevated_token_from_request<Req: AuthRequest>(
        &self,
        req: &Req,
    ) -> Option<Self::ElevatedToken> {
        self.elevation.tokens.extract(req)
    }
}
