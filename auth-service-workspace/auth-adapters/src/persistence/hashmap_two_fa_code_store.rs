use std::collections::HashMap;

use auth_core::{Email, TwoFaAttemptId, TwoFaCode, TwoFaCodeStore, TwoFaCodeStoreError};

#[derive(Default)]
pub struct HashMapTwoFaCodeStore {
    codes: HashMap<Email, (TwoFaAttemptId, TwoFaCode)>,
}

impl HashMapTwoFaCodeStore {
    pub fn new() -> Self {
        Self {
            codes: HashMap::new(),
        }
    }
}

#[async_trait::async_trait]
impl TwoFaCodeStore for HashMapTwoFaCodeStore {
    async fn store_code(
        &mut self,
        user_id: Email,
        login_attempt_id: TwoFaAttemptId,
        two_fa_code: TwoFaCode,
    ) -> Result<(), TwoFaCodeStoreError> {
        self.codes.insert(user_id, (login_attempt_id, two_fa_code));
        Ok(())
    }

    async fn validate(
        &self,
        user_id: &Email,
        login_attempt_id: &TwoFaAttemptId,
        two_fa_code: &TwoFaCode,
    ) -> Result<(), TwoFaCodeStoreError> {
        let Some((id, code)) = self.codes.get(user_id) else {
            return Err(TwoFaCodeStoreError::UserNotFound);
        };

        if id != login_attempt_id {
            return Err(TwoFaCodeStoreError::InvalidAttemptId);
        }
        if code != two_fa_code {
            return Err(TwoFaCodeStoreError::Invalid2FACode);
        }
        Ok(())
    }

    async fn get_login_attempt_id_and_two_fa_code(
        &self,
        user_id: &Email,
    ) -> Result<(TwoFaAttemptId, TwoFaCode), TwoFaCodeStoreError> {
        let Some((id, code)) = self.codes.get(user_id) else {
            return Err(TwoFaCodeStoreError::UserNotFound);
        };
        Ok((id.clone(), code.clone()))
    }

    async fn delete(&mut self, user_id: &Email) -> Result<(), TwoFaCodeStoreError> {
        self.codes
            .remove(user_id)
            .ok_or(TwoFaCodeStoreError::UserNotFound)?;
        Ok(())
    }
}
