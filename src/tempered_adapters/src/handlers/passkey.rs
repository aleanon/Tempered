//! Framework-agnostic passkey (WebAuthn) handlers.
//!
//! Registration is for an **already authenticated** user: both registration
//! handlers take the caller's `email`, which the delivery layer must read from
//! the validated session (never from the request body).
//!
//! Each ceremony is JSON in / JSON out. The three non-login steps return their
//! options/result directly; only `login_finish` delivers a token, which it does
//! by reusing the scheme's `create_login_response` (so the passkey session
//! cookie is identical to a password-login one).

use serde_json::json;
use tempered_core::{
    Email, HttpAuthenticationScheme, HttpResponseBuilderExt, LoginOutcome, ResponseBuilder,
    SupportsPasskeys, WebAuthnChallenge,
};

use crate::handlers::HandlerError;

/// Registration leg 1: return creation options for the authenticated user.
pub async fn handle_passkey_register_start<S, B>(
    scheme: &S,
    email: Email,
    builder: B,
) -> Result<B::Response, HandlerError<S::PasskeyError>>
where
    S: SupportsPasskeys,
    B: ResponseBuilder,
{
    let options = scheme
        .start_passkey_registration(email)
        .await
        .map_err(HandlerError::Auth)?;
    Ok(builder.status(200).json_body(options).build()?)
}

/// Registration leg 2: verify the attestation and enroll the credential.
pub async fn handle_passkey_register_finish<S, B>(
    scheme: &S,
    email: Email,
    challenge: WebAuthnChallenge,
    response: serde_json::Value,
    builder: B,
) -> Result<B::Response, HandlerError<S::PasskeyError>>
where
    S: SupportsPasskeys,
    B: ResponseBuilder,
{
    scheme
        .finish_passkey_registration(email, challenge, response)
        .await
        .map_err(HandlerError::Auth)?;
    Ok(builder
        .status(200)
        .json_body(json!({ "status": "registered" }))
        .build()?)
}

/// Authentication leg 1: return request options (`email = None` for usernameless).
pub async fn handle_passkey_login_start<S, B>(
    scheme: &S,
    email: Option<Email>,
    builder: B,
) -> Result<B::Response, HandlerError<S::PasskeyError>>
where
    S: SupportsPasskeys,
    B: ResponseBuilder,
{
    let options = scheme
        .start_passkey_authentication(email)
        .await
        .map_err(HandlerError::Auth)?;
    Ok(builder.status(200).json_body(options).build()?)
}

/// Authentication leg 2: verify the assertion and deliver the primary token.
pub async fn handle_passkey_login_finish<S, B>(
    scheme: &S,
    challenge: WebAuthnChallenge,
    response: serde_json::Value,
    builder: B,
) -> Result<B::Response, HandlerError<S::PasskeyError>>
where
    S: SupportsPasskeys + HttpAuthenticationScheme,
    B: ResponseBuilder,
{
    let token = scheme
        .finish_passkey_authentication(challenge, response)
        .await
        .map_err(HandlerError::Auth)?;
    // Reuse the scheme's normal login delivery (sets the auth cookie).
    Ok(scheme.create_login_response(builder, LoginOutcome::Success(token))?)
}
