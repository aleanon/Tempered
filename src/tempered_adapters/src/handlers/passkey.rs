//! Framework-agnostic passkey (WebAuthn) handlers.
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

/// Registration leg 1: return creation options for an enrolling user.
pub async fn handle_passkey_register_start<S, B>(
    scheme: &S,
    email: Email,
    builder: B,
) -> Result<B::Response, S::PasskeyError>
where
    S: SupportsPasskeys,
    B: ResponseBuilder,
{
    let options = scheme.start_passkey_registration(email).await?;
    Ok(builder
        .status(200)
        .json_body(options)
        .build()
        .expect("ResponseBuilder error building passkey options - this is a bug"))
}

/// Registration leg 2: verify the attestation and enroll the credential.
pub async fn handle_passkey_register_finish<S, B>(
    scheme: &S,
    challenge: WebAuthnChallenge,
    response: serde_json::Value,
    builder: B,
) -> Result<B::Response, S::PasskeyError>
where
    S: SupportsPasskeys,
    B: ResponseBuilder,
{
    scheme.finish_passkey_registration(challenge, response).await?;
    Ok(builder
        .status(200)
        .json_body(json!({ "status": "registered" }))
        .build()
        .expect("ResponseBuilder error building passkey response - this is a bug"))
}

/// Authentication leg 1: return request options (`email = None` for usernameless).
pub async fn handle_passkey_login_start<S, B>(
    scheme: &S,
    email: Option<Email>,
    builder: B,
) -> Result<B::Response, S::PasskeyError>
where
    S: SupportsPasskeys,
    B: ResponseBuilder,
{
    let options = scheme.start_passkey_authentication(email).await?;
    Ok(builder
        .status(200)
        .json_body(options)
        .build()
        .expect("ResponseBuilder error building passkey options - this is a bug"))
}

/// Authentication leg 2: verify the assertion and deliver the primary token.
pub async fn handle_passkey_login_finish<S, B>(
    scheme: &S,
    challenge: WebAuthnChallenge,
    response: serde_json::Value,
    builder: B,
) -> Result<B::Response, S::PasskeyError>
where
    S: SupportsPasskeys + HttpAuthenticationScheme,
    B: ResponseBuilder,
{
    let token = scheme
        .finish_passkey_authentication(challenge, response)
        .await?;
    // Reuse the scheme's normal login delivery (sets the auth cookie).
    Ok(scheme
        .create_login_response(builder, LoginOutcome::Success(token))
        .expect("ResponseBuilder error in create_login_response - this is a bug in the scheme"))
}
