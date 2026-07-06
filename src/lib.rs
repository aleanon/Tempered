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
    ApiKeyId, CredentialId, Email, EmailVerificationToken, OAuthProviderConfig, OAuthUserInfo,
    PasskeyCredential, Password, SessionId, TwoFaAttemptId, TwoFaCode, TwoFaError, User, UserError,
    ValidatedUser, WebAuthnChallenge,
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
    ChallengeStore, ChallengeStoreError, EmailClient, EmailVerificationStoreError,
    EmailVerificationTokenStore, HttpOAuth2Scheme, OAuthHttpClient, OAuthHttpError,
    OAuthIdentityStore, OAuthStateStore, PasskeyCredentialStore, PasskeyStoreError,
    RequiresEmailVerification, SessionStore, SessionStoreError, SupportsApiKeyIssuance,
    SupportsOAuth2, SupportsPasskeys, TwoFaCodeStore, TwoFaCodeStoreError, UserStore,
    UserStoreError, WebAuthnVerifier,
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
        Authz, CredentialError, CredentialScheme, ElevatedCapabilities, RouteFlags,
    },
    authentication::jwt_scheme::{
        Elevation, EmailVerify, JwtScheme, OAuth, Passkeys, PasswordReset, TwoFa,
    },
    authentication::session_scheme::{
        SessionClaims, SessionConfig, SessionError, SessionScheme, SessionToken, SessionTokens,
    },
    authentication::token_strategy::{JwtToken, JwtTokens, TokenStrategy},
    email::MockEmailClient,
    oauth::{OAuthFlow, OAuthFlowError},
    passkey::{PasskeyFlow, PasskeyFlowError},
    persistence::{
        HashMapApiKeyStore, HashMapChallengeStore, HashMapEmailVerificationTokenStore,
        HashMapOAuthIdentityStore, HashMapOAuthStateStore, HashMapPasskeyCredentialStore,
        HashMapPasswordResetTokenStore, HashMapSessionStore, HashMapTokenEpochStore,
        HashMapTwoFaCodeStore, HashMapUserStore, HashSetBannedTokenStore,
    },
};

// Feature-gated heavy backends (see the crate features in Cargo.toml).
#[cfg(feature = "postgres")]
pub use tempered_adapters::persistence::PostgresUserStore;
#[cfg(feature = "redis")]
pub use tempered_adapters::persistence::{
    RedisBannedTokenStore, RedisPasswordResetTokenStore, RedisTokenEpochStore,
    RedisTwoFaCodeStore,
};
#[cfg(feature = "oauth-client")]
pub use tempered_adapters::oauth::ReqwestOAuthHttpClient;
#[cfg(feature = "postmark-email")]
pub use tempered_adapters::email::PostmarkEmailClient;

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
    AuthService, PathOverrides, auth_service,
    middleware::{validate_elevated_token, validate_token},
};

// ============================================================================
// Re-export common external dependencies
// ============================================================================

/// Re-export async-trait for implementing repository traits
pub use async_trait::async_trait;

/// Re-export secrecy for working with secrets
pub use secrecy::{ExposeSecret, Secret};

pub use http;
