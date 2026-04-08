pub mod composable;
pub mod domain;
pub mod http_abstraction;
pub mod http_authentication_scheme;
pub mod http_error;
pub mod ports;
pub mod strategies;

// Re-export commonly used types for convenience
pub use domain::{
    email::Email,
    password::Password,
    two_fa_attempt_id::TwoFaAttemptId,
    two_fa_code::TwoFaCode,
    two_fa_error::TwoFaError,
    user::{User, UserError, ValidatedUser},
};

pub use ports::{
    repositories::{
        BannedTokenStore, BannedTokenStoreError, TwoFaCodeStore, TwoFaCodeStoreError, UserStore,
        UserStoreError,
    },
    services::EmailClient,
};

pub use strategies::{
    auth_validator::AuthValidator,
    authenticator::{
        AuthenticationScheme, LoginOutcome, SupportsAccountDeletion, SupportsElevation,
        SupportsOAuth2, SupportsPasswordChange, SupportsPasswordReset, SupportsRegistration,
        SupportsTokenRevocation, SupportsTwoFactor,
    },
};

pub use http_abstraction::{
    AuthRequest, AuthResponseBuilder, AuthResponseHelpers, HttpResponseBuilderExt, ResponseBuilder,
    ResponseBuilderError,
};
pub use http_authentication_scheme::{HttpAuthenticationScheme, HttpElevationScheme};
pub use http_error::IntoStatusMessage;
