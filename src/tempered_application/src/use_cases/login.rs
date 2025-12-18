use tempered_core::{
    Email, EmailClient, Password, TwoFaAttemptId, TwoFaCode, TwoFaCodeStore, TwoFaCodeStoreError,
    UserStore, UserStoreError, ValidatedUser,
};

/// Response from login use case
#[derive(Debug, PartialEq)]
pub enum LoginResponse {
    /// User authenticated successfully without 2FA
    Success(Email),
    /// User requires 2FA, return attempt ID
    Requires2Fa {
        email: Email,
        attempt_id: TwoFaAttemptId,
    },
}

/// Error types specific to login use case
#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error("User store error: {0}")]
    UserStoreError(#[from] UserStoreError),
    #[error("2FA code store error: {0}")]
    TwoFaCodeStoreError(#[from] TwoFaCodeStoreError),
    #[error("Failed to send email: {0}")]
    EmailError(String),
}

/// Login use case - handles user authentication
pub struct LoginUseCase<U, T, E>
where
    U: UserStore,
    T: TwoFaCodeStore,
    E: EmailClient,
{
    user_store: U,
    two_fa_code_store: T,
    email_client: E,
}

impl<U, T, E> LoginUseCase<U, T, E>
where
    U: UserStore,
    T: TwoFaCodeStore,
    E: EmailClient,
{
    pub fn new(user_store: U, two_fa_code_store: T, email_client: E) -> Self {
        Self {
            user_store,
            two_fa_code_store,
            email_client,
        }
    }

    /// Execute the login use case
    ///
    /// # Arguments
    /// * `email` - User's email address
    /// * `password` - User's password
    ///
    /// # Returns
    /// LoginResponse indicating whether user needs 2FA or is authenticated
    #[tracing::instrument(name = "LoginUseCase::execute", skip(self, password))]
    pub async fn execute(
        &self,
        email: Email,
        password: Password,
    ) -> Result<LoginResponse, LoginError> {
        // Authenticate user credentials
        let validated_user = self.user_store.authenticate_user(&email, &password).await?;

        match validated_user {
            ValidatedUser::Requires2Fa(email) => self.handle_2fa_required(email).await,
            ValidatedUser::No2Fa(email) => Ok(LoginResponse::Success(email)),
        }
    }

    /// Handle 2FA required scenario
    async fn handle_2fa_required(&self, email: Email) -> Result<LoginResponse, LoginError> {
        let login_attempt_id = TwoFaAttemptId::new();
        let code = TwoFaCode::new();

        // Store the 2FA code
        self.two_fa_code_store
            .store_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await?;

        // Send the 2FA code via email
        self.email_client
            .send_email(&email, "2FA Code", code.as_str())
            .await
            .map_err(|e| LoginError::EmailError(e.to_string()))?;

        Ok(LoginResponse::Requires2Fa {
            email,
            attempt_id: login_attempt_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::{ExposeSecret, Secret};

    // Mock implementations for testing
    #[derive(Clone)]
    struct MockUserStore {
        email: String,
        password: String,
        requires_2fa: bool,
    }

    #[async_trait::async_trait]
    impl UserStore for MockUserStore {
        async fn add_user(&self, _user: tempered_core::User) -> Result<(), UserStoreError> {
            unimplemented!()
        }

        async fn set_new_password(
            &self,
            _email: &Email,
            _new_password: Password,
        ) -> Result<(), UserStoreError> {
            unimplemented!()
        }

        async fn authenticate_user(
            &self,
            email: &Email,
            password: &Password,
        ) -> Result<ValidatedUser, UserStoreError> {
            if email.as_ref().expose_secret() == &self.email
                && password.as_ref().expose_secret() == &self.password
            {
                Ok(ValidatedUser::new(email.clone(), self.requires_2fa))
            } else {
                Err(UserStoreError::IncorrectPassword)
            }
        }

        async fn get_user(&self, _email: &Email) -> Result<tempered_core::User, UserStoreError> {
            unimplemented!()
        }

        async fn delete_user(&self, _user: &Email) -> Result<(), UserStoreError> {
            unimplemented!()
        }
    }

    #[derive(Clone)]
    struct MockTwoFaCodeStore;

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
            unimplemented!()
        }

        async fn get_login_attempt_id_and_two_fa_code(
            &self,
            _user_id: &Email,
        ) -> Result<(TwoFaAttemptId, TwoFaCode), TwoFaCodeStoreError> {
            unimplemented!()
        }

        async fn delete(&self, _user_id: &Email) -> Result<(), TwoFaCodeStoreError> {
            unimplemented!()
        }
    }

    #[derive(Clone)]
    struct MockEmailClient;

    #[async_trait::async_trait]
    impl EmailClient for MockEmailClient {
        async fn send_email(
            &self,
            _recipient: &Email,
            _subject: &str,
            _content: &str,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_login_without_2fa() {
        let user_store = MockUserStore {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            requires_2fa: false,
        };
        let two_fa_store = MockTwoFaCodeStore;
        let email_client = MockEmailClient;

        let use_case = LoginUseCase::new(user_store, two_fa_store, email_client);

        let email = Email::try_from(Secret::from("test@example.com".to_string())).unwrap();
        let password = Password::try_from(Secret::from("password123".to_string())).unwrap();

        let result = use_case.execute(email.clone(), password).await;
        assert!(matches!(result, Ok(LoginResponse::Success(_))));
    }

    #[tokio::test]
    async fn test_login_with_2fa() {
        let user_store = MockUserStore {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            requires_2fa: true,
        };
        let two_fa_store = MockTwoFaCodeStore;
        let email_client = MockEmailClient;

        let use_case = LoginUseCase::new(user_store, two_fa_store, email_client);

        let email = Email::try_from(Secret::from("test@example.com".to_string())).unwrap();
        let password = Password::try_from(Secret::from("password123".to_string())).unwrap();

        let result = use_case.execute(email, password).await;
        assert!(matches!(result, Ok(LoginResponse::Requires2Fa { .. })));
    }
}
