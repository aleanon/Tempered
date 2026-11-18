//! OAuth2 / OIDC authorization-code support.

pub mod flow;
pub mod pkce;
#[cfg(feature = "oauth-client")]
pub mod reqwest_client;

pub use flow::{AuthorizationRequest, OAuthFlow, OAuthFlowError, VerifiedIdentity};
pub use pkce::pkce_challenge_s256;
#[cfg(feature = "oauth-client")]
pub use reqwest_client::ReqwestOAuthHttpClient;
