//! OAuth2 / OIDC authorization-code support.

pub mod flow;
mod id_token;
pub mod pkce;
pub mod providers;
#[cfg(feature = "oauth-client")]
pub mod reqwest_client;

pub use flow::{AuthorizationRequest, OAuthFlow, OAuthFlowError, VerifiedIdentity};
pub use pkce::pkce_challenge_s256;
#[cfg(feature = "oauth-client")]
pub use reqwest_client::ReqwestOAuthHttpClient;
