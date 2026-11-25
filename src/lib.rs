//! # tempered — composable backend authentication
//!
//! `tempered` is a facade crate that re-exports the common public surface of the
//! workspace so you can reach it through one dependency. Pick a scheme
//! ([`JwtScheme`], [`SessionScheme`], [`ApiKeyScheme`]), enable the capabilities
//! you want with its `supports_*` builders, and serve it with the axum adapter.
//!
//! ## Usage
//!
//! Add to your `Cargo.toml`:
//! ```toml
//! [dependencies]
//! tempered = { path = "../tempered" }
//! ```
//!
//! Then build a scheme and hand it to [`auth_service`]. See the crate
//! `README.md` and the `examples/` directory for runnable code.
//!
//! ## Structure
//!
//! - **Core domain types**: [`Email`], [`Password`], [`User`], etc.
//! - **Repository/port traits**: [`UserStore`], [`BannedTokenStore`],
//!   [`TwoFaCodeStore`], [`EmailClient`], etc. — implement these to swap backends.
//! - **Schemes**: [`JwtScheme`], [`SessionScheme`], [`ApiKeyScheme`], built on
//!   [`CredentialScheme`] + [`TokenStrategy`].
//! - **Adapters**: [`PostgresUserStore`], [`RedisBannedTokenStore`],
//!   [`PostmarkEmailClient`], and the in-memory `HashMap*` stores for dev/tests.
//!
//! - **Delivery**: [`auth_service`] / [`AuthService`] (the axum layer,
//!   re-exported from `tempered_axum`; also available as [`axum_service`]).

// ============================================================================
// Core Domain Types
// ============================================================================

/// Core domain types and value objects
pub mod core {
    pub use tempered_core::*;
}

// Re-export most commonly used core types at the root level
pub use tempered_core::{
    ApiKeyId, CeremonyId, CeremonyKind, CeremonyStart, CeremonyState, CredentialId, Email,
    EmailVerificationToken, IdentityClaims, MAX_PASSWORD_CHARS, MIN_PASSWORD_CHARS,
    OAuthProviderConfig, OAuthUserInfo, OidcSettings, PasskeyCredential, Password,
    PendingAuthorization, SessionId, TokenResponse, TwoFaAttemptId, TwoFaCode, TwoFaError, User,
    UserError, ValidatedUser,
};

// ============================================================================
// Repository Traits (Ports)
// ============================================================================

/// Repository trait definitions
pub mod repositories {
    pub use tempered_core::{
        BannedTokenStore, BannedTokenStoreError, TwoFaCodeStore, TwoFaCodeStoreError, UserStore,
        UserStoreError,
    };
}

// Re-export repository traits at root level
pub use core::{
    ApiKeyStore, ApiKeyStoreError, AuthorizationRequest, BannedTokenStore, BannedTokenStoreError,
    ChallengeStore, ChallengeStoreError, ClassifyError, EmailClient, EmailVerificationStoreError,
    EmailVerificationTokenStore, ErrorCategory, HttpOAuth2Scheme, Mail, OAuthHttpClient,
    OAuthHttpError, OAuthIdentityStore, OAuthStateStore, PasskeyCredentialStore, PasskeyStoreError,
    RateLimitStore, RateLimitStoreError, RecoveryCodeHash, RefreshRecord, RefreshTokenStore,
    RefreshTokenStoreError, RequiresEmailVerification, SessionRecord, SessionSeen, SessionStore,
    SessionStoreError, SupportsApiKeyIssuance, SupportsEmailLogin, SupportsOAuth2,
    SupportsPasskeys, SupportsTotp, TotpEnrollment, TotpStore, TotpStoreError, TwoFaCodeStore,
    TwoFaCodeStoreError, UserStore, UserStoreError, WebAuthnVerifier, WindowCount,
};

// ============================================================================
// Adapters (Infrastructure)
// ============================================================================

/// Infrastructure adapters
pub mod adapters {

    /// Persistence implementations
    pub mod persistence {
        pub use tempered_adapters::persistence::*;
    }

    /// Email client implementations
    pub mod email {
        pub use tempered_adapters::email::*;
    }

    /// JWT authentication utilities
    pub mod auth {
        pub use tempered_adapters::auth_validation::*;
    }
}

// Re-export commonly used adapters at root level
pub use tempered_adapters::{
    auth_validation::local_jwt_validator::{Claims, JwtAuthConfig},
    authentication::api_key_scheme::{ApiKeyClaims, ApiKeyScheme, Issuance},
    authentication::credential_scheme::{
        Authz, CredentialError, CredentialScheme, DEFAULT_OAUTH_STATE_COOKIE, ElevatedCapabilities,
        ElevatedRevokeError, EmailLogin, OAUTH_TWO_FA_COOKIE, RouteFlags,
    },
    authentication::deferred::{DeferredJob, DeferredRunner},
    authentication::jwt_scheme::{
        Elevation, EmailVerify, JwtScheme, OAuth, Passkeys, PasswordReset, TwoFa,
    },
    authentication::rate_limit::{Limit, RateLimitGroup, RateLimiter, RateLimits},
    authentication::session_scheme::{
        DEFAULT_MAX_SESSION_LIFETIME_SECONDS, SessionClaims, SessionConfig, SessionError,
        SessionScheme, SessionTicket, SessionToken, SessionTokens,
    },
    authentication::token_strategy::{
        ClaimsProvider, JwtTicket, JwtToken, JwtTokens, MIN_JWT_SECRET_BYTES, RefreshTokens,
        SessionInfo, TokenStrategy, USER_LOCK_TTL_SECONDS, UserLock,
    },
    authentication::totp::{RECOVERY_CODES, Totp},
    email::MockEmailClient,
    oauth::{OAuthFlow, OAuthFlowError, VerifiedIdentity, pkce_challenge_s256},
    passkey::{PasskeyFlow, PasskeyFlowError},
    persistence::{
        Argon2Hasher, Argon2Params, HashMapApiKeyStore, HashMapChallengeStore,
        HashMapEmailVerificationTokenStore, HashMapOAuthIdentityStore, HashMapOAuthStateStore,
        HashMapPasskeyCredentialStore, HashMapPasswordResetTokenStore, HashMapRateLimitStore,
        HashMapRefreshTokenStore, HashMapSessionStore, HashMapTokenEpochStore, HashMapTotpStore,
        HashMapTwoFaCodeStore, HashMapUserStore, HashSetBannedTokenStore, PasswordVerdict,
    },
};

// Feature-gated heavy backends (see the crate features in Cargo.toml).
#[cfg(feature = "breached-passwords")]
pub use tempered_adapters::authentication::breached::BreachedPasswordCheck;
#[cfg(feature = "postmark-email")]
pub use tempered_adapters::email::PostmarkEmailClient;
#[cfg(feature = "oauth-client")]
pub use tempered_adapters::oauth::ReqwestOAuthHttpClient;
#[cfg(feature = "passkeys-webauthn")]
pub use tempered_adapters::passkey::{WebAuthnRsVerifier, webauthn_rs};
#[cfg(feature = "postgres")]
pub use tempered_adapters::persistence::{
    PostgresApiKeyStore, PostgresOAuthIdentityStore, PostgresPasskeyCredentialStore,
    PostgresTotpStore, PostgresUserStore,
};
#[cfg(feature = "redis")]
pub use tempered_adapters::persistence::{
    RedisBannedTokenStore, RedisChallengeStore, RedisEmailVerificationTokenStore,
    RedisOAuthStateStore, RedisPasswordResetTokenStore, RedisRateLimitStore,
    RedisRefreshTokenStore, RedisSessionStore, RedisTokenEpochStore, RedisTwoFaCodeStore,
};

// ============================================================================
// Axum service layer
// ============================================================================

/// The axum delivery layer (service builder, middleware, wiring, routes)
pub mod axum_service {
    pub use tempered_axum::*;
}

// Re-export the service entry points at root level: `auth_service(scheme, assets)`
// builds the fully-wired service; `validate_token` / `validate_elevated_token`
// are the middleware behind `.validated_router()` / `.validated_elevated_router()`.
pub use tempered_axum::{
    AuthService, IntoStatusMessage, PathOverrides, RouteId, Tier, auth_service,
    middleware::{require_scope, validate_elevated_token, validate_token},
};

/// Ready-made OAuth/OIDC provider settings (Google, Microsoft, GitHub) and
/// OIDC discovery.
pub mod oauth_providers {
    pub use tempered_adapters::oauth::providers::*;
}

pub use tempered_adapters::endpoints::{AuthEvent, AuthEventSink, ClientAddr};

/// The framework-neutral route table (for writing an adapter for another web
/// framework; see `docs/ROUTE_TABLE_DESIGN.md`).
pub mod endpoints {
    pub use tempered_adapters::endpoints::*;
}

// ============================================================================
// Re-export common external dependencies
// ============================================================================

/// The scheme traits: what a scheme can do (each `supports_*` builder adds one).
pub use tempered_core::{
    AuthenticationScheme, SupportsAccountDeletion, SupportsElevation, SupportsPasswordChange,
    SupportsPasswordReset, SupportsRegistration, SupportsTokenRevocation, SupportsTwoFactor,
};

/// Re-export async-trait for implementing repository traits
pub use async_trait::async_trait;

/// Re-export secrecy for working with secrets
pub use secrecy::{ExposeSecret, Secret};

pub use http;
