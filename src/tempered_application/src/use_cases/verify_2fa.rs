use tempered_core::{
    Email, TwoFaAttemptId, TwoFaCode, TwoFaCodeStore, TwoFaCodeStoreError, TwoFaError,
};

/// Error types for verify 2FA use case
#[derive(Debug, thiserror::Error)]
pub enum Verify2FaError {
    #[error("2FA code store error: {0}")]
    TwoFaCodeStoreError(#[from] TwoFaCodeStoreError),
    #[error("2FA error: {0}")]
    TwoFaError(#[from] TwoFaError),
    #[error("Invalid login attempt ID")]
    InvalidLoginAttemptId,
    #[error("Invalid 2FA code")]
    InvalidTwoFaCode,
}

/// Verify 2FA use case - validates 2FA code and login attempt
pub struct Verify2FaUseCase<T>
where
    T: TwoFaCodeStore,
{
    two_fa_code_store: T,
}

impl<T> Verify2FaUseCase<T>
where
    T: TwoFaCodeStore,
{
    pub fn new(two_fa_code_store: T) -> Self {
        Self { two_fa_code_store }
    }

    /// Execute the verify 2FA use case
    ///
    /// # Arguments
    /// * `email` - User's email address
    /// * `login_attempt_id` - The login attempt ID from login response
    /// * `two_fa_code` - The 2FA code received via email
    ///
    /// # Returns
    /// Ok(Email) on successful verification, or Verify2FaError
    #[tracing::instrument(name = "Verify2FaUseCase::execute", skip(self))]
    pub async fn execute(
        &self,
        email: Email,
        login_attempt_id: TwoFaAttemptId,
        two_fa_code: TwoFaCode,
    ) -> Result<Email, Verify2FaError> {
        // Get stored attempt ID and code
        let (stored_attempt_id, stored_two_fa_code) = self
            .two_fa_code_store
            .get_login_attempt_id_and_two_fa_code(&email)
            .await?;

        // Verify attempt ID matches
        if stored_attempt_id != login_attempt_id {
            return Err(Verify2FaError::InvalidLoginAttemptId);
        }

        // Verify 2FA code matches
        if stored_two_fa_code != two_fa_code {
            return Err(Verify2FaError::InvalidTwoFaCode);
        }

        // Delete the used code
        self.two_fa_code_store.delete(&email).await?;

        Ok(email)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::{ExposeSecret, Secret};

    #[derive(Clone)]
    struct MockTwoFaCodeStore {
        email: String,
        attempt_id: TwoFaAttemptId,
        code: TwoFaCode,
    }

    #[async_trait::async_trait]
    impl TwoFaCodeStore for MockTwoFaCodeStore {
        async fn store_code(
            &self,
            _user_id: Email,
            _login_attempt_id: TwoFaAttemptId,
            _two_fa_code: TwoFaCode,
        ) -> Result<(), TwoFaCodeStoreError> {
            Ok(())
        }

        async fn validate(
            &self,
            _user_id: &Email,
            _login_attempt_id: &TwoFaAttemptId,
            _two_fa_code: &TwoFaCode,
        ) -> Result<(), TwoFaCodeStoreError> {
            Ok(())
        }

        async fn get_login_attempt_id_and_two_fa_code(
            &self,
            email: &Email,
        ) -> Result<(TwoFaAttemptId, TwoFaCode), TwoFaCodeStoreError> {
            if email.as_ref().expose_secret() == &self.email {
                Ok((self.attempt_id.clone(), self.code.clone()))
            } else {
                Err(TwoFaCodeStoreError::UserNotFound)
            }
        }

        async fn delete(&self, _user_id: &Email) -> Result<(), TwoFaCodeStoreError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_verify_2fa_success() {
        let attempt_id = TwoFaAttemptId::new();
        let code = TwoFaCode::new();
        let email = Email::try_from(Secret::from("test@example.com".to_string())).unwrap();

        let store = MockTwoFaCodeStore {
            email: "test@example.com".to_string(),
            attempt_id: attempt_id.clone(),
            code: code.clone(),
        };

        let use_case = Verify2FaUseCase::new(store);
        let result = use_case.execute(email.clone(), attempt_id, code).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), email);
    }

    #[tokio::test]
    async fn test_verify_2fa_invalid_code() {
        let attempt_id = TwoFaAttemptId::new();
        let correct_code = TwoFaCode::new();
        let wrong_code = TwoFaCode::new();
        let email = Email::try_from(Secret::from("test@example.com".to_string())).unwrap();

        let store = MockTwoFaCodeStore {
            email: "test@example.com".to_string(),
            attempt_id: attempt_id.clone(),
            code: correct_code,
        };

        let use_case = Verify2FaUseCase::new(store);
        let result = use_case.execute(email, attempt_id, wrong_code).await;

        assert!(matches!(result, Err(Verify2FaError::InvalidTwoFaCode)));
    }
}
