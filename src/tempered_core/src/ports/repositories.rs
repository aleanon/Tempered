use async_trait::async_trait;
use secrecy::Secret;
use thiserror::Error;

use crate::domain::{
    api_key::ApiKeyId,
    email::Email,
    email_verification_token::EmailVerificationToken,
    oauth::PendingAuthorization,
    passkey::{CeremonyId, CredentialId, PasskeyCredential, PendingCeremony},
    password::Password,
    password_reset_token::PasswordResetToken,
    session_id::SessionId,
    two_fa_attempt_id::TwoFaAttemptId,
    two_fa_code::TwoFaCode,
    user::{User, ValidatedUser},
};

// UserStore port trait and errors
#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Incorrect password")]
    IncorrectPassword,
    #[error("Unexpected error {0}")]
    UnexpectedError(#[source] crate::error::Failure),
}

impl PartialEq for UserStoreError {
    /// Equal when the variants match; an `UnexpectedError` message is ignored.
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

#[async_trait]
pub trait UserStore: Send + Sync {
    /// Add `user`, or fail with `UserAlreadyExists` if the address is taken.
    ///
    /// A store that hashes passwords should hash before it finds out the
    /// address is taken: signup answers a taken address like a new one, and
    /// a quicker failure would tell the two apart by timing.
    async fn add_user(&self, user: User) -> Result<(), UserStoreError>;
    async fn set_new_password(
        &self,
        email: &Email,
        new_password: Password,
    ) -> Result<(), UserStoreError>;
    async fn authenticate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<ValidatedUser, UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    /// Turn the account's 2FA requirement on or off, leaving everything else
    /// about it unchanged. Fails with [`UserStoreError::UserNotFound`] if
    /// there is no such account.
    async fn set_requires_2fa(
        &self,
        email: &Email,
        requires_2fa: bool,
    ) -> Result<(), UserStoreError>;
    async fn delete_user(&self, user: &Email) -> Result<(), UserStoreError>;
}

// BannedTokenStore port trait and errors
#[derive(Debug, Error)]
pub enum BannedTokenStoreError {
    #[error("Database error: {0}")]
    DatabaseError(String),
}

#[async_trait]
pub trait BannedTokenStore: Send + Sync {
    async fn ban_token(&self, token: String) -> Result<(), BannedTokenStoreError>;
    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError>;
}

// TokenEpochStore port trait and errors
#[derive(Debug, Error)]
pub enum TokenEpochStoreError {
    #[error("Unexpected error: {0}")]
    UnexpectedError(#[source] crate::error::Failure),
}

/// Per-user revocation cutoffs ("token epochs") for token schemes with no
/// server-side session registry (JWTs).
///
/// Global revocation for such schemes works by recording a per-user cutoff
/// instant: validation rejects any token whose issued-at (`iat`) is strictly
/// before the cutoff. `revoke_before(email, now)` therefore invalidates every
/// outstanding token for the user at once (password change, account deletion,
/// "log out everywhere").
///
/// Contract: a stored cutoff MUST remain readable for at least the longest
/// token TTL — if it expires earlier, a revoked (or deleted account's) token
/// becomes valid again for the rest of its lifetime.
#[async_trait]
pub trait TokenEpochStore: Send + Sync {
    /// Earliest issued-at (unix seconds) still valid for this user;
    /// `None` = no cutoff recorded.
    async fn min_valid_iat(&self, email: &Email) -> Result<Option<i64>, TokenEpochStoreError>;

    /// Invalidate every token issued *strictly before* `cutoff` (unix
    /// seconds). Implementations MUST keep the highest cutoff seen, never
    /// lower it.
    async fn revoke_before(&self, email: &Email, cutoff: i64) -> Result<(), TokenEpochStoreError>;

    /// Try to take the user's **credential lock** for `ttl_seconds`, as
    /// `holder`. Returns `false` if someone else holds it.
    ///
    /// The lock makes "remove this user's credentials" and "store a new
    /// credential for this user" mutually exclusive, and logins are refused
    /// while it is held. Implementations MUST make the take atomic
    /// (compare-and-set) and MUST let the lock expire after `ttl_seconds`, so
    /// a holder that crashed cannot lock the user out.
    async fn try_lock_user(
        &self,
        email: &Email,
        holder: &str,
        ttl_seconds: u64,
    ) -> Result<bool, TokenEpochStoreError>;

    /// Release the user's credential lock, if `holder` still holds it. A lock
    /// that expired and was taken by someone else MUST be left alone.
    async fn unlock_user(&self, email: &Email, holder: &str) -> Result<(), TokenEpochStoreError>;

    /// Whether anyone holds the user's credential lock right now.
    async fn is_user_locked(&self, email: &Email) -> Result<bool, TokenEpochStoreError>;
}

// TwoFaCodeStore port trait and errors
#[derive(Debug, Error)]
pub enum TwoFaCodeStoreError {
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid session")]
    InvalidAttemptId,
    #[error("Invalid 2FA code")]
    Invalid2FACode,
    #[error("Too many failed attempts")]
    TooManyAttempts,
    #[error("2FA code expired")]
    CodeExpired,
    #[error("Unexpected error")]
    UnexpectedError(#[source] crate::error::Failure),
}

#[cfg(debug_assertions)]
impl PartialEq for TwoFaCodeStoreError {
    /// Equal when the variants match; an `UnexpectedError` message is ignored.
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

// PasswordResetTokenStore port trait and errors
//
// Maps token → email so complete_password_reset can recover the email from only the token.
#[derive(Debug, Error)]
pub enum PasswordResetTokenStoreError {
    #[error("Token not found")]
    TokenNotFound,
    #[error("Unexpected error: {0}")]
    UnexpectedError(#[source] crate::error::Failure),
}

#[async_trait]
pub trait PasswordResetTokenStore: Send + Sync {
    async fn store_token(
        &self,
        token: PasswordResetToken,
        email: Email,
    ) -> Result<(), PasswordResetTokenStoreError>;

    async fn get_email_for_token(
        &self,
        token: &PasswordResetToken,
    ) -> Result<Email, PasswordResetTokenStoreError>;

    async fn delete_token(
        &self,
        token: &PasswordResetToken,
    ) -> Result<(), PasswordResetTokenStoreError>;

    /// Retrieve and remove the email for a token in one atomic step, so a
    /// reset token cannot be redeemed twice by concurrent requests. Mirrors
    /// [`EmailVerificationTokenStore::consume_token`].
    async fn consume_token(
        &self,
        token: &PasswordResetToken,
    ) -> Result<Email, PasswordResetTokenStoreError>;

    /// Remove every outstanding reset token for `email`, succeeding when
    /// there are none.
    ///
    /// Called when the account's credentials change or the account is
    /// deleted. A token mailed before then must not survive it: otherwise
    /// whoever re-registers a deleted address within the token's lifetime
    /// has their password reset by the old link, and a link sitting in a
    /// compromised mailbox outlives the password change meant to lock the
    /// intruder out.
    async fn delete_all_for_user(&self, email: &Email) -> Result<(), PasswordResetTokenStoreError>;
}

// EmailVerificationTokenStore port trait and errors
#[derive(Debug, Error)]
pub enum EmailVerificationStoreError {
    #[error("Token not found or expired")]
    TokenNotFound,
    #[error("Unexpected error: {0}")]
    UnexpectedError(#[source] crate::error::Failure),
}

/// Maps verification tokens to emails (pending verifications) and tracks verified status.
#[async_trait]
pub trait EmailVerificationTokenStore: Send + Sync {
    /// Store a pending verification token for the given email.
    async fn store_pending_verification(
        &self,
        token: EmailVerificationToken,
        email: Email,
    ) -> Result<(), EmailVerificationStoreError>;

    /// Retrieve and remove the email associated with a token.
    async fn consume_token(
        &self,
        token: &EmailVerificationToken,
    ) -> Result<Email, EmailVerificationStoreError>;

    /// Mark an email address as verified.
    async fn mark_verified(&self, email: &Email) -> Result<(), EmailVerificationStoreError>;

    /// Check whether the email address has been verified.
    async fn is_verified(&self, email: &Email) -> Result<bool, EmailVerificationStoreError>;

    /// Forget everything held for `email`: its verified mark and any pending
    /// verification tokens. Called when the account is deleted, so the proof
    /// cannot be inherited by a later account that reuses the address.
    /// Succeeds when there is nothing to forget.
    async fn forget_email(&self, email: &Email) -> Result<(), EmailVerificationStoreError>;
}

// Passkey (WebAuthn) ports and errors
#[derive(Debug, Error)]
pub enum PasskeyStoreError {
    #[error("Credential not found")]
    CredentialNotFound,
    #[error("Credential id is already registered")]
    CredentialAlreadyExists,
    /// The new signature counter does not advance the stored one: a replayed
    /// or cloned authenticator's assertion, or one that lost a race.
    #[error("Signature counter did not advance")]
    SignCountNotAdvanced,
    #[error("Unexpected error: {0}")]
    UnexpectedError(#[source] crate::error::Failure),
}

#[async_trait]
pub trait PasskeyCredentialStore: Send + Sync {
    /// Store a newly enrolled credential.
    ///
    /// Must fail with [`PasskeyStoreError::CredentialAlreadyExists`] if the
    /// credential id is already present, for any owner. Overwriting would hand
    /// an existing credential — and the account it logs in to — to a new owner.
    async fn add_credential(&self, cred: PasskeyCredential) -> Result<(), PasskeyStoreError>;
    async fn get_credential(
        &self,
        id: &CredentialId,
    ) -> Result<PasskeyCredential, PasskeyStoreError>;
    async fn list_for_user(
        &self,
        owner: &Email,
    ) -> Result<Vec<PasskeyCredential>, PasskeyStoreError>;

    /// Record a successful authentication: set the signature counter and, when
    /// `credential_data` is `Some`, replace the stored opaque credential data.
    ///
    /// Only if `new_sign_count` is greater than the stored counter, or both
    /// are 0 (an authenticator without a counter); otherwise fail with
    /// [`PasskeyStoreError::SignCountNotAdvanced`] and change nothing. The
    /// check and the write MUST be one atomic step (a conditional `UPDATE`),
    /// so two concurrent logins with the same assertion cannot both succeed.
    async fn update_after_authentication(
        &self,
        id: &CredentialId,
        new_sign_count: u32,
        credential_data: Option<Vec<u8>>,
    ) -> Result<(), PasskeyStoreError>;

    /// Remove every credential owned by `owner` (account deletion).
    ///
    /// Idempotent: succeeds when the user has none. After it returns `Ok`, no
    /// credential previously enrolled for `owner` may be returned by
    /// [`get_credential`](Self::get_credential) or
    /// [`list_for_user`](Self::list_for_user) — otherwise a later account
    /// created with the same email would inherit the old owner's passkeys.
    async fn delete_all_for_user(&self, owner: &Email) -> Result<(), PasskeyStoreError>;

    /// Remove one of `owner`'s credentials; `false` if they have none by
    /// that id (another user's id is "none").
    async fn delete_credential(
        &self,
        owner: &Email,
        id: &CredentialId,
    ) -> Result<bool, PasskeyStoreError>;

    /// Rename one of `owner`'s credentials; `false` if they have none by
    /// that id.
    async fn rename_credential(
        &self,
        owner: &Email,
        id: &CredentialId,
        name: Option<String>,
    ) -> Result<bool, PasskeyStoreError>;
}

#[derive(Debug, Error)]
pub enum ChallengeStoreError {
    #[error("Challenge not found or expired")]
    ChallengeNotFound,
    #[error("Unexpected error: {0}")]
    UnexpectedError(#[source] crate::error::Failure),
}

/// Holds in-flight WebAuthn ceremonies between their `start` and `finish` legs:
/// the verifier's opaque challenge state and the user the ceremony is for.
///
/// Entries are single-use and should expire after a short TTL (minutes). The
/// state is server-side only; the client only ever sees the [`CeremonyId`].
#[async_trait]
pub trait ChallengeStore: Send + Sync {
    async fn store_ceremony(
        &self,
        id: CeremonyId,
        ceremony: PendingCeremony,
    ) -> Result<(), ChallengeStoreError>;

    /// Consume a ceremony. Succeeds at most once per stored id: a second call
    /// (a replayed `finish`) must fail with
    /// [`ChallengeStoreError::ChallengeNotFound`].
    async fn consume_ceremony(
        &self,
        id: &CeremonyId,
    ) -> Result<PendingCeremony, ChallengeStoreError>;

    /// Drop every pending ceremony bound to `user` (usernameless ceremonies
    /// carry no user and are untouched). Called when the user's credentials
    /// are removed: an enrolment started before that must not finish after it.
    async fn delete_all_for_user(&self, user: &Email) -> Result<(), ChallengeStoreError>;
}

// OAuth ports and errors
#[derive(Debug, Error)]
pub enum OAuthStateStoreError {
    #[error("Unknown or expired state")]
    UnknownState,
    #[error("Unexpected error: {0}")]
    UnexpectedError(#[source] crate::error::Failure),
}

/// Stores each in-flight authorization request — the provider it was sent to
/// and its PKCE `code_verifier` — under its single-use anti-CSRF `state`,
/// between the authorize redirect and the callback.
///
/// Production implementations should apply a short TTL (minutes) and consume
/// atomically.
#[async_trait]
pub trait OAuthStateStore: Send + Sync {
    /// Persist a pending authorization request under its `state`.
    async fn store_state(
        &self,
        state: String,
        pending: PendingAuthorization,
    ) -> Result<(), OAuthStateStoreError>;

    /// Consume a `state` value, returning the request stored with it.
    ///
    /// Succeeds at most once per stored state: a second call (a replayed
    /// callback) must fail with [`OAuthStateStoreError::UnknownState`].
    async fn consume_state(
        &self,
        state: &str,
    ) -> Result<PendingAuthorization, OAuthStateStoreError>;
}

#[derive(Debug, Error)]
pub enum OAuthIdentityStoreError {
    #[error("Identity already linked to a different account")]
    AlreadyLinked,
    #[error("Unexpected error: {0}")]
    UnexpectedError(#[source] crate::error::Failure),
}

/// Maps an external provider identity `(provider, subject)` to a local user email.
#[async_trait]
pub trait OAuthIdentityStore: Send + Sync {
    /// Link a provider identity to a local email.
    ///
    /// Idempotent when the identity already maps to the *same* email, but must
    /// fail with [`OAuthIdentityStoreError::AlreadyLinked`] if `(provider,
    /// subject)` is already bound to a *different* email — silently moving the
    /// binding would enable account takeover. Re-linking to a different account
    /// must be a deliberate, re-authenticated action.
    async fn link_identity(
        &self,
        provider: String,
        subject: String,
        email: Email,
    ) -> Result<(), OAuthIdentityStoreError>;

    /// Find the local email previously linked to a provider identity.
    async fn find_email(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<Email>, OAuthIdentityStoreError>;

    /// Whether any provider identity is linked to `email`.
    ///
    /// A linked identity means a provider has already proven the address
    /// belongs to the account's user, so a later first login through another
    /// provider can trust the account as it is.
    async fn has_identity_for_email(&self, email: &Email) -> Result<bool, OAuthIdentityStoreError>;

    /// The provider identities linked to `email`, as `(provider, subject)`.
    async fn list_for_user(
        &self,
        email: &Email,
    ) -> Result<Vec<(String, String)>, OAuthIdentityStoreError>;

    /// Remove `email`'s link to `provider`; `false` if there was none.
    async fn unlink(&self, email: &Email, provider: &str) -> Result<bool, OAuthIdentityStoreError>;

    /// Remove every provider identity linked to `email`. Called when the
    /// account is deleted: a link is a way to log in to that account, and
    /// proof of its address, and neither may pass to a later account that
    /// reuses the address. Succeeds when there is nothing to remove.
    async fn unlink_all_for_email(&self, email: &Email) -> Result<(), OAuthIdentityStoreError>;
}

// ApiKeyStore port, records and errors
//
// Keys are stored as a SHA-256 hash of the secret half only — the plaintext is
// shown to the caller exactly once at creation and never persisted.
#[derive(Debug, Clone)]
pub struct ApiKeyRecord {
    pub id: ApiKeyId,
    /// Non-secret lookup handle (the part before the `.`).
    pub prefix: String,
    /// Hex SHA-256 of the secret half.
    pub secret_hash: String,
    pub owner: Email,
    pub scopes: Vec<String>,
    /// Unix seconds.
    pub created_at: u64,
    /// Unix seconds after which the key is refused; `None` never expires.
    pub expires_at: Option<u64>,
    /// When the key was last used (recorded at most about once a minute).
    pub last_used_at: Option<u64>,
}

/// Non-secret metadata returned when listing a user's keys.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyMetadata {
    pub id: ApiKeyId,
    pub prefix: String,
    pub scopes: Vec<String>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub last_used_at: Option<u64>,
}

#[derive(Debug, Error)]
pub enum ApiKeyStoreError {
    #[error("API key not found")]
    NotFound,
    #[error("API key prefix already in use")]
    PrefixTaken,
    #[error("Unexpected error: {0}")]
    UnexpectedError(#[source] crate::error::Failure),
}

#[async_trait]
pub trait ApiKeyStore: Send + Sync {
    /// Persist a newly-issued key record. Never overwrites: a record whose
    /// prefix is already stored fails with [`ApiKeyStoreError::PrefixTaken`]
    /// (the issuer draws a new key and tries again).
    async fn create_key(&self, record: ApiKeyRecord) -> Result<(), ApiKeyStoreError>;

    /// Look up a key record by its non-secret prefix.
    async fn find_by_prefix(&self, prefix: &str) -> Result<ApiKeyRecord, ApiKeyStoreError>;

    /// Revoke (delete) `owner`'s key `id`. A key that does not exist and a
    /// key that belongs to someone else both fail with
    /// [`ApiKeyStoreError::NotFound`], so a caller cannot revoke, or learn
    /// about, another user's keys.
    async fn revoke_key(&self, owner: &Email, id: &ApiKeyId) -> Result<(), ApiKeyStoreError>;

    /// List non-secret metadata for all of a user's keys.
    async fn list_for_user(&self, owner: &Email) -> Result<Vec<ApiKeyMetadata>, ApiKeyStoreError>;

    /// Delete every key `owner` holds, succeeding when there are none. Call
    /// it when the account is deleted: a key does not check that its owner
    /// still exists.
    async fn delete_all_for_owner(&self, owner: &Email) -> Result<(), ApiKeyStoreError>;

    /// Record that key `id` was used at `at` (Unix seconds). Best effort:
    /// a failure must not refuse the request.
    async fn record_use(&self, id: &ApiKeyId, at: u64) -> Result<(), ApiKeyStoreError>;
}

// SessionStore port trait and errors
//
// Backs the opaque server-side session scheme: maps a random SessionId to the
// authenticated user's email. Deleting an entry instantly revokes the session.
#[derive(Debug, Error)]
pub enum SessionStoreError {
    #[error("Session not found")]
    SessionNotFound,
    #[error("Unexpected error: {0}")]
    UnexpectedError(#[source] crate::error::Failure),
}

/// What a [`SessionStore`] keeps for a session: whose it is, when it was
/// created (Unix seconds), and which kind of session it is.
///
/// The creation time is what caps a session's age: sliding expiry alone
/// would let a session that is used often live forever.
///
/// `scope` names the strategy that issued the session (the scheme uses its
/// cookie name, so a login session and an elevated one differ). A validator
/// accepts only its own scope, so a login session id placed in the elevated
/// cookie is refused even when both kinds share one store. It never
/// contains `:`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub email: Email,
    pub created_at: u64,
    pub scope: String,
    /// When the session was last used (Unix seconds), for the user's device
    /// list. Set by [`touch_session`](SessionStore::touch_session).
    pub last_seen: Option<u64>,
    /// The `User-Agent` of the first request the session was used for (the
    /// device it was opened on). Set once by
    /// [`touch_session`](SessionStore::touch_session).
    pub user_agent: Option<String>,
}

/// What a request that uses a session tells its store.
#[derive(Debug, Clone, Copy)]
pub struct SessionSeen<'a> {
    /// Unix seconds.
    pub at: u64,
    pub user_agent: Option<&'a str>,
}

#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Create a new session. Store `record` as given: the scheme sets the
    /// creation time, and [`get_session`](Self::get_session) must return it
    /// unchanged.
    async fn create_session(
        &self,
        id: SessionId,
        record: SessionRecord,
    ) -> Result<(), SessionStoreError>;

    /// Look up a session without changing its expiry.
    async fn get_session(&self, id: &SessionId) -> Result<SessionRecord, SessionStoreError>;

    /// Look up a session and restart its idle timeout (sliding expiry), in
    /// one step: the scheme calls this, not [`get_session`](Self::get_session),
    /// on every authenticated request, so a store should make it a single
    /// round trip. A missing session is
    /// [`SessionNotFound`](SessionStoreError::SessionNotFound). In-memory
    /// stores without expiry just read.
    ///
    /// Also record `seen`: set `last_seen` to `seen.at`, and `user_agent`
    /// to `seen.user_agent` if the session has none yet (the first device
    /// stays). Return the record as it was before this request.
    async fn touch_session(
        &self,
        id: &SessionId,
        seen: SessionSeen<'_>,
    ) -> Result<SessionRecord, SessionStoreError>;

    /// The user's live sessions, for their device list.
    async fn list_for_user(
        &self,
        email: &Email,
    ) -> Result<Vec<(SessionId, SessionRecord)>, SessionStoreError>;

    /// Delete a single session (logout).
    async fn delete_session(&self, id: &SessionId) -> Result<(), SessionStoreError>;

    /// Delete every session belonging to a user (logout-everywhere / password change).
    ///
    /// Contract: implementations MUST advance the user's
    /// [`revocation_count`](Self::revocation_count) **before** deleting, so a
    /// login racing this call either sees the new count or has its session
    /// deleted here.
    async fn delete_all_for_user(&self, email: &Email) -> Result<(), SessionStoreError>;

    /// How many times `delete_all_for_user` has run for this user (0 if never).
    ///
    /// The session strategy reads this when a login begins and again after
    /// creating the session: a change means the user's sessions were revoked
    /// while the login was in flight, and the new session is discarded.
    /// Implementations MUST keep the count at least as long as a login can
    /// take; it never needs to decrease.
    async fn revocation_count(&self, email: &Email) -> Result<u64, SessionStoreError>;

    /// Try to take the user's **credential lock** for `ttl_seconds`, as
    /// `holder`. Returns `false` if someone else holds it.
    ///
    /// The lock makes "remove this user's credentials" and "store a new
    /// credential for this user" mutually exclusive, and logins are refused
    /// while it is held. Implementations MUST make the take atomic
    /// (compare-and-set) and MUST let the lock expire after `ttl_seconds`, so
    /// a holder that crashed cannot lock the user out.
    async fn try_lock_user(
        &self,
        email: &Email,
        holder: &str,
        ttl_seconds: u64,
    ) -> Result<bool, SessionStoreError>;

    /// Release the user's credential lock, if `holder` still holds it. A lock
    /// that expired and was taken by someone else MUST be left alone.
    async fn unlock_user(&self, email: &Email, holder: &str) -> Result<(), SessionStoreError>;

    /// Whether anyone holds the user's credential lock right now.
    async fn is_user_locked(&self, email: &Email) -> Result<bool, SessionStoreError>;
}

#[async_trait]
pub trait TwoFaCodeStore: Send + Sync {
    /// Where this store keeps its codes, when it can say: two stores with
    /// the same keyspace share codes. Used to refuse, at startup, a second
    /// store (passwordless email login) that would share the 2FA store's
    /// codes. `None` (the default) means "cannot tell".
    fn keyspace(&self) -> Option<String> {
        None
    }

    async fn store_code(
        &self,
        user_id: Email,
        login_attempt_id: TwoFaAttemptId,
        two_fa_code: TwoFaCode,
    ) -> Result<(), TwoFaCodeStoreError>;

    /// Check a presented code against the stored one and, if it matches,
    /// remove it: a code logs in once.
    ///
    /// Contract (all of it atomic, across instances too; a check followed by
    /// a separate update lets parallel requests slip through):
    /// - **Single use.** On success the code is gone, so concurrent
    ///   submissions of the right code succeed at most once.
    /// - **Bounded guessing per account.** Count failed codes per user, in a
    ///   window that a new code does NOT reset (otherwise logging in again
    ///   buys a fresh budget). At the cap, delete any stored code and return
    ///   [`TwoFaCodeStoreError::TooManyAttempts`], also for codes issued later
    ///   in the window. Success clears the count.
    /// - **Expiry.** A stored code expires; an expired or absent code fails
    ///   with [`TwoFaCodeStoreError::CodeExpired`] or
    ///   [`TwoFaCodeStoreError::UserNotFound`].
    ///
    /// A 6-digit code is brute-forceable without all three.
    async fn redeem_code(
        &self,
        user_id: &Email,
        login_attempt_id: &TwoFaAttemptId,
        two_fa_code: &TwoFaCode,
    ) -> Result<(), TwoFaCodeStoreError>;

    async fn get_login_attempt_id_and_two_fa_code(
        &self,
        user_id: &Email,
    ) -> Result<(TwoFaAttemptId, TwoFaCode), TwoFaCodeStoreError>;

    async fn delete(&self, user_id: &Email) -> Result<(), TwoFaCodeStoreError>;
}

// ============================================================================
// Rate limiting
// ============================================================================

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RateLimitStoreError {
    #[error("Unexpected error: {0}")]
    UnexpectedError(#[source] crate::error::Failure),
}

/// The state of one counter after a hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowCount {
    /// Hits in the current window, this one included.
    pub count: u64,
    /// Seconds until the window ends and the count starts again.
    pub resets_in_seconds: u64,
}

/// Fixed-window hit counters, for rate limits.
///
/// Keys are opaque strings the caller builds (route group, then an account
/// or a client address). A store only counts.
#[async_trait]
pub trait RateLimitStore: Send + Sync {
    /// Count one hit against `key` and return the count so far in its
    /// window. The first hit on a key (or the first after its window ended)
    /// opens a window of `window_seconds`; later hits in it do not extend
    /// it. The increment must be atomic across instances: a read followed by
    /// a separate write lets parallel requests through uncounted.
    async fn hit(&self, key: &str, window_seconds: u64)
    -> Result<WindowCount, RateLimitStoreError>;
}

// ============================================================================
// TOTP (authenticator apps) and recovery codes
// ============================================================================

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TotpStoreError {
    #[error("Unexpected error: {0}")]
    UnexpectedError(#[source] crate::error::Failure),
}

/// SHA-256 of a recovery code. Recovery codes are random (50 bits), so a
/// fast hash is enough: there is no dictionary to try.
pub type RecoveryCodeHash = [u8; 32];

/// Per-user TOTP secrets and recovery codes.
///
/// A user has at most one *pending* secret (being enrolled: shown to them,
/// not yet confirmed with a code) and one *active* secret (what logins
/// check). Confirming moves pending to active, so enrolling a new
/// authenticator does not break the old one until the new one works.
///
/// Secrets are login credentials: keep them in durable storage, and
/// encrypted at rest if the database is not.
#[async_trait]
pub trait TotpStore: Send + Sync {
    /// Keep `secret` as the user's pending secret, replacing any pending one.
    async fn set_pending(
        &self,
        email: &Email,
        secret: Secret<Vec<u8>>,
    ) -> Result<(), TotpStoreError>;

    async fn pending(&self, email: &Email) -> Result<Option<Secret<Vec<u8>>>, TotpStoreError>;

    /// In one atomic step: make the pending secret active (dropping the old
    /// active one), record `used_step` as its last used time step, and
    /// replace the recovery codes with `recovery_codes`. `false`, changing
    /// nothing, if there is no pending secret.
    async fn activate(
        &self,
        email: &Email,
        used_step: u64,
        recovery_codes: Vec<RecoveryCodeHash>,
    ) -> Result<bool, TotpStoreError>;

    async fn active(&self, email: &Email) -> Result<Option<Secret<Vec<u8>>>, TotpStoreError>;

    /// Record `step` as used if it is later than the last one used, in one
    /// atomic step; `false` if it is not (a replayed code, or one from an
    /// earlier step than a code already accepted).
    async fn use_step(&self, email: &Email, step: u64) -> Result<bool, TotpStoreError>;

    /// Replace the user's recovery codes.
    async fn replace_recovery_codes(
        &self,
        email: &Email,
        recovery_codes: Vec<RecoveryCodeHash>,
    ) -> Result<(), TotpStoreError>;

    /// Remove `code` from the user's recovery codes, in one atomic step;
    /// `false` if it is not one of them. Each code works once.
    async fn use_recovery_code(
        &self,
        email: &Email,
        code: &RecoveryCodeHash,
    ) -> Result<bool, TotpStoreError>;

    /// Forget the user's secrets and recovery codes. Succeeds when there are
    /// none.
    async fn delete_all_for_user(&self, email: &Email) -> Result<(), TotpStoreError>;
}

// ============================================================================
// Refresh tokens
// ============================================================================

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RefreshTokenStoreError {
    /// Not a refresh token this store issued, or one that has expired or
    /// been revoked.
    #[error("Unknown or expired refresh token")]
    NotFound,
    /// A refresh token that was already used. Rotation means each is used
    /// once, so a second use is a stolen copy (or the thief's, and this is
    /// the owner): the store has revoked the whole family.
    #[error("Refresh token reused")]
    Reused { email: Email },
    #[error("Unexpected error: {0}")]
    UnexpectedError(#[source] crate::error::Failure),
}

/// SHA-256 of a refresh token. Tokens are 256 random bits, so a fast hash
/// is enough, and a leaked store holds nothing that can be presented.
pub type RefreshTokenHash = [u8; 32];

/// One refresh token, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshRecord {
    pub email: Email,
    /// All tokens rotated from one login share a family; reusing any of
    /// them revokes it.
    pub family: String,
    /// Unix seconds after which the token is refused.
    pub expires_at: u64,
}

/// Rotating refresh tokens with reuse detection (OAuth 2.0 Security BCP
/// §4.14).
#[async_trait]
pub trait RefreshTokenStore: Send + Sync {
    /// Store a new, unused token. Refuse it with
    /// [`NotFound`](RefreshTokenStoreError::NotFound) if its family was
    /// revoked (for at least as long as a rotation can take): otherwise a
    /// rotation that redeemed a token just before the revocation would
    /// bring the family back.
    async fn create(
        &self,
        token: RefreshTokenHash,
        record: RefreshRecord,
    ) -> Result<(), RefreshTokenStoreError>;

    /// Use a token, in one atomic step: an unused, unexpired token becomes
    /// used and its record is returned. A used token revokes its family and
    /// answers [`Reused`](RefreshTokenStoreError::Reused); an unknown,
    /// expired or revoked one answers
    /// [`NotFound`](RefreshTokenStoreError::NotFound). Used tokens must be
    /// remembered until they expire, or reuse goes unnoticed.
    async fn redeem(
        &self,
        token: &RefreshTokenHash,
    ) -> Result<RefreshRecord, RefreshTokenStoreError>;

    /// Revoke a family (logout), in one atomic step with the refusal of new
    /// tokens in it. Succeeds for an unknown family.
    async fn revoke_family(&self, family: &str) -> Result<(), RefreshTokenStoreError>;

    /// Revoke every family of the user (password change, account
    /// deletion), each as [`revoke_family`](Self::revoke_family) does. Must
    /// reach every family whose tokens can still be redeemed.
    async fn revoke_all_for_user(&self, email: &Email) -> Result<(), RefreshTokenStoreError>;
}
