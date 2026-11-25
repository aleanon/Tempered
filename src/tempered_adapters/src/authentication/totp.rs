//! TOTP (authenticator app) second factor and recovery codes.
//!
//! RFC 6238 with the parameters every authenticator app supports: HMAC-SHA1,
//! 30-second steps, six digits, a 160-bit secret. A code is accepted for the
//! current step and one step either side (clock drift), and each step works
//! once per user (a code seen over someone's shoulder cannot be replayed).
//!
//! Recovery codes stand in for the app when it is lost: ten single-use
//! codes, made at enrolment, stored as SHA-256 hashes and shown once.

use std::sync::Arc;

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, Secret};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tempered_core::{Email, RecoveryCodeHash, TotpStore, TotpStoreError, TwoFaCode};

/// Seconds per TOTP step.
const STEP_SECONDS: u64 = 30;
/// Secret length in bytes (160 bits, RFC 4226's recommendation).
const SECRET_BYTES: usize = 20;
/// Recovery codes made at enrolment.
pub const RECOVERY_CODES: usize = 10;

/// The TOTP part of the 2FA slot: a [`TotpStore`] and the issuer name the
/// authenticator app shows next to the account (your app's name).
#[derive(Clone)]
pub struct Totp<TS> {
    pub(crate) store: TS,
    pub(crate) issuer: Arc<str>,
}

impl<TS> Totp<TS> {
    pub fn new(store: TS, issuer: impl Into<String>) -> Self {
        Self {
            store,
            issuer: issuer.into().into(),
        }
    }
}

/// What the 2FA slot asks of its TOTP part. `()` is "no TOTP".
#[async_trait]
pub(crate) trait TotpFactor: Send + Sync {
    /// Whether `email` answers 2FA with an app (has an active secret).
    async fn uses_totp(&self, email: &Email) -> Result<bool, TotpStoreError>;

    /// Whether `code` is a valid app code or unused recovery code for
    /// `email`. Consumes it when it is.
    async fn accept(&self, email: &Email, code: &TwoFaCode) -> Result<bool, TotpStoreError>;

    /// Forget the user's TOTP data (account deletion).
    async fn forget(&self, email: &Email) -> Result<(), TotpStoreError>;
}

#[async_trait]
impl TotpFactor for () {
    async fn uses_totp(&self, _: &Email) -> Result<bool, TotpStoreError> {
        Ok(false)
    }
    async fn accept(&self, _: &Email, _: &TwoFaCode) -> Result<bool, TotpStoreError> {
        Ok(false)
    }
    async fn forget(&self, _: &Email) -> Result<(), TotpStoreError> {
        Ok(())
    }
}

#[async_trait]
impl<TS: TotpStore> TotpFactor for Totp<TS> {
    async fn uses_totp(&self, email: &Email) -> Result<bool, TotpStoreError> {
        Ok(self.store.active(email).await?.is_some())
    }

    async fn accept(&self, email: &Email, code: &TwoFaCode) -> Result<bool, TotpStoreError> {
        if code.is_recovery_code() {
            return self
                .store
                .use_recovery_code(email, &hash_recovery_code(code))
                .await;
        }
        let Some(secret) = self.store.active(email).await? else {
            return Ok(false);
        };
        match matching_step(secret.expose_secret(), code, unix_now()) {
            Some(step) => self.store.use_step(email, step).await,
            None => Ok(false),
        }
    }

    async fn forget(&self, email: &Email) -> Result<(), TotpStoreError> {
        self.store.delete_all_for_user(email).await
    }
}

/// A new random secret.
pub(crate) fn new_secret() -> Secret<Vec<u8>> {
    let mut secret = vec![0u8; SECRET_BYTES];
    rand::fill(&mut secret[..]);
    Secret::new(secret)
}

/// The `otpauth://` URI an authenticator app reads (usually from a QR code).
pub(crate) fn otpauth_uri(issuer: &str, email: &Email, secret: &[u8]) -> String {
    let label = format!("{issuer}:{}", email.as_ref().expose_secret());
    let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    format!(
        "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period={STEP_SECONDS}",
        enc(&label).replace('+', "%20"),
        base32(secret),
        enc(issuer).replace('+', "%20"),
    )
}

/// The step `code` is valid for at `now` (the current one or a neighbour),
/// or `None`.
pub(crate) fn matching_step(secret: &[u8], code: &TwoFaCode, now: u64) -> Option<u64> {
    let current = now / STEP_SECONDS;
    [current, current.saturating_sub(1), current + 1]
        .into_iter()
        .find(|&step| {
            let expected = format!("{:06}", code_at(secret, step));
            tempered_core::constant_time_eq(&expected, code)
        })
}

/// RFC 4226 HOTP value for `counter`, six digits.
fn code_at(secret: &[u8], counter: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC takes a key of any length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let value = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    value % 1_000_000
}

/// Fresh recovery codes: what to show the user (`abcde-fghij`) and what to
/// store.
pub(crate) fn new_recovery_codes() -> (Vec<String>, Vec<RecoveryCodeHash>) {
    (0..RECOVERY_CODES)
        .map(|_| {
            let code = TwoFaCode::new_recovery_code();
            let shown = format!("{}-{}", &code[..5], &code[5..]);
            (shown, hash_recovery_code(&code))
        })
        .unzip()
}

fn hash_recovery_code(code: &TwoFaCode) -> RecoveryCodeHash {
    Sha256::digest(code.as_bytes()).into()
}

/// RFC 4648 base32 without padding, as authenticator apps expect secrets.
pub(crate) fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The app's code `offset` steps from now, for tests that play the
/// authenticator app (`1` is the next step, which is still accepted).
#[cfg(test)]
pub(crate) fn code_for(secret: &[u8], offset: u64) -> TwoFaCode {
    let step = unix_now() / STEP_SECONDS + offset;
    TwoFaCode::parse(format!("{:06}", code_at(secret, step))).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B, SHA-1, with the RFC's 20-byte secret.
    #[test]
    fn matches_the_rfc_6238_test_vectors() {
        let secret = b"12345678901234567890";
        for (time, expected) in [
            (59u64, 94287082u32),
            (1111111109, 7081804),
            (1111111111, 14050471),
            (1234567890, 89005924),
            (2000000000, 69279037),
        ] {
            // The RFC lists eight digits; six are its last six.
            assert_eq!(
                code_at(secret, time / STEP_SECONDS),
                expected % 1_000_000,
                "t={time}"
            );
        }
    }

    #[test]
    fn a_code_is_good_for_its_step_and_the_neighbours_only() {
        let secret = b"12345678901234567890";
        let now = 1111111111;
        let code = |step: u64| TwoFaCode::parse(format!("{:06}", code_at(secret, step))).unwrap();
        let current = now / STEP_SECONDS;
        assert_eq!(matching_step(secret, &code(current), now), Some(current));
        assert_eq!(
            matching_step(secret, &code(current - 1), now),
            Some(current - 1)
        );
        assert_eq!(
            matching_step(secret, &code(current + 1), now),
            Some(current + 1)
        );
        assert_eq!(matching_step(secret, &code(current + 3), now), None);
    }

    #[test]
    fn base32_matches_rfc_4648() {
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(b"foob"), "MZXW6YQ");
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn the_otpauth_uri_names_issuer_account_and_secret() {
        let email = Email::try_from(Secret::new("a@example.com".to_string())).unwrap();
        let uri = otpauth_uri("My App", &email, b"foobar");
        assert_eq!(
            uri,
            "otpauth://totp/My%20App%3Aa%40example.com?secret=MZXW6YTBOI&issuer=My%20App&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn recovery_codes_are_shown_split_and_hashed_like_their_input() {
        let (shown, hashes) = new_recovery_codes();
        assert_eq!(shown.len(), RECOVERY_CODES);
        let typed = TwoFaCode::parse(shown[3].to_uppercase()).unwrap();
        assert_eq!(hash_recovery_code(&typed), hashes[3]);
    }
}
