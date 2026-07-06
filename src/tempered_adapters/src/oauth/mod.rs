//! OAuth2 / OIDC authorization-code support.

pub mod flow;
#[cfg(feature = "oauth-client")]
pub mod reqwest_client;

pub use flow::{AuthorizationRequest, OAuthFlow, OAuthFlowError};
#[cfg(feature = "oauth-client")]
pub use reqwest_client::ReqwestOAuthHttpClient;
