pub mod domain;
pub mod error;
pub mod http_abstraction;
pub mod http_authentication_scheme;
pub mod ports;
pub mod strategies;
pub mod util;

// Re-export commonly used types for convenience
pub use domain::{
    api_key::ApiKeyId,
    email::Email,
    email_verification_token::EmailVerificationToken,
    oauth::{
        OAuthProviderConfig, OAuthUserInfo, OidcSettings, PendingAuthorization, TokenResponse,
    },
    passkey::{
        CeremonyId, CeremonyKind, CeremonyStart, CeremonyState, CredentialId, PasskeyCeremony,
        PasskeyCredential, PendingCeremony,
    },
    password::{MAX_PASSWORD_CHARS, MIN_PASSWORD_CHARS, Password},
    password_reset_token::PasswordResetToken,
    session_id::SessionId,
    two_fa_attempt_id::TwoFaAttemptId,
    two_fa_code::TwoFaCode,
    two_fa_error::TwoFaError,
    user::{User, UserError, ValidatedUser},
};

pub use ports::{
    repositories::{
        ApiKeyMetadata, ApiKeyRecord, ApiKeyStore, ApiKeyStoreError, BannedTokenStore,
        BannedTokenStoreError, ChallengeStore, ChallengeStoreError, EmailVerificationStoreError,
        EmailVerificationTokenStore, OAuthIdentityStore, OAuthIdentityStoreError, OAuthStateStore,
        OAuthStateStoreError, PasskeyCredentialStore, PasskeyStoreError, PasswordResetTokenStore,
        PasswordResetTokenStoreError, RateLimitStore, RateLimitStoreError, RecoveryCodeHash,
        RefreshRecord, RefreshTokenHash, RefreshTokenStore, RefreshTokenStoreError, SessionRecord,
        SessionSeen, SessionStore, SessionStoreError, TokenEpochStore, TokenEpochStoreError,
        TotpStore, TotpStoreError, TwoFaCodeStore, TwoFaCodeStoreError, UserStore, UserStoreError,
        WindowCount,
    },
    services::{
        EmailClient, OAuthHttpClient, OAuthHttpError, VerifiedAssertion, VerifiedRegistration,
        WebAuthnError, WebAuthnVerifier,
    },
};

pub use strategies::{
    auth_validator::{AuthValidator, IdentityClaims},
    authenticator::{
        AuthenticationScheme, AuthorizationRequest, LoginOutcome, RequiresEmailVerification,
        SupportsAccountDeletion, SupportsApiKeyIssuance, SupportsElevation, SupportsEmailLogin,
        SupportsOAuth2, SupportsPasskeys, SupportsPasswordChange, SupportsPasswordReset,
        SupportsRegistration, SupportsTokenRevocation, SupportsTotp, SupportsTwoFactor,
        TotpEnrollment,
    },
};

pub use error::{ClassifyError, ErrorCategory};
pub use http_abstraction::{
    AuthRequest, AuthResponseHelpers, HttpResponseBuilderExt, ResponseBuilder, ResponseBuilderError,
};
pub use http_authentication_scheme::{
    HttpAuthenticationScheme, HttpElevationScheme, HttpOAuth2Scheme,
};
pub use util::constant_time_eq;
