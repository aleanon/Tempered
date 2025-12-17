use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use auth_core::{Email, TwoFaAttemptId, TwoFaCode, TwoFaCodeStore, TwoFaCodeStoreError};

#[derive(Default, Clone)]
pub struct HashMapTwoFaCodeStore {
    codes: Arc<RwLock<HashMap<Email, (TwoFaAttemptId, TwoFaCode)>>>,
}

impl HashMapTwoFaCodeStore {
    pub fn new() -> Self {
        Self {
            codes: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl TwoFaCodeStore for HashMapTwoFaCodeStore {
    async fn store_code(
        &self,
        user_id: Email,
        login_attempt_id: TwoFaAttemptId,
        two_fa_code: TwoFaCode,
    ) -> Result<(), TwoFaCodeStoreError> {
        let mut codes = self.codes.write().await;
        codes.insert(user_id, (login_attempt_id, two_fa_code));
        Ok(())
    }

    async fn validate(
        &self,
        user_id: &Email,
        login_attempt_id: &TwoFaAttemptId,
        two_fa_code: &TwoFaCode,
    ) -> Result<(), TwoFaCodeStoreError> {
        let codes = self.codes.read().await;
        let Some((id, code)) = codes.get(user_id) else {
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
        let codes = self.codes.read().await;
        let Some((id, code)) = codes.get(user_id) else {
            return Err(TwoFaCodeStoreError::UserNotFound);
        };
        Ok((id.clone(), code.clone()))
    }

    async fn delete(&self, user_id: &Email) -> Result<(), TwoFaCodeStoreError> {
        let mut codes = self.codes.write().await;
        codes
            .remove(user_id)
            .ok_or(TwoFaCodeStoreError::UserNotFound)?;
        Ok(())
    }
}
