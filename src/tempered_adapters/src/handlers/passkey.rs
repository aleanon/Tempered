//! Framework-agnostic passkey (WebAuthn) handlers.
//!
//! Registration is for an **already authenticated** user: both registration
//! handlers take the caller's `email`, which the delivery layer must read from
//! the validated session (never from the request body).
//!
//! Each ceremony is JSON in / JSON out. A `start` leg returns
//! `{ "ceremony_id", "options" }`; the three non-login steps return their
//! result directly; only `login_finish` delivers a token, which it does
//! by reusing the scheme's `create_login_response` (so the passkey session
//! cookie is identical to a password-login one).

use secrecy::ExposeSecret;
use serde_json::json;
use tempered_core::{
    CeremonyId, Email, HttpAuthenticationScheme, HttpResponseBuilderExt, LoginOutcome,
    PasskeyCeremony, ResponseBuilder, SupportsPasskeys,
};

use crate::handlers::HandlerError;

/// The JSON a `start` leg returns: `options` goes to `navigator.credentials`,
/// `ceremony_id` is sent back verbatim with the result on the `finish` leg.
fn ceremony_body(ceremony: PasskeyCeremony) -> serde_json::Value {
    json!({
        "ceremony_id": ceremony.ceremony_id.as_str(),
        "options": ceremony.options,
    })
}

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
    let ceremony = scheme
        .start_passkey_registration(email)
        .await
        .map_err(HandlerError::Auth)?;
    Ok(builder
        .status(200)
        .json_body(ceremony_body(ceremony))
        .build()?)
}

/// Registration leg 2: verify the attestation and enroll the credential.
pub async fn handle_passkey_register_finish<S, B>(
    scheme: &S,
    email: Email,
    ceremony_id: CeremonyId,
    response: serde_json::Value,
    builder: B,
) -> Result<B::Response, HandlerError<S::PasskeyError>>
where
    S: SupportsPasskeys,
    B: ResponseBuilder,
{
    scheme
        .finish_passkey_registration(email, ceremony_id, response)
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
    let ceremony = scheme
        .start_passkey_authentication(email)
        .await
        .map_err(HandlerError::Auth)?;
    Ok(builder
        .status(200)
        .json_body(ceremony_body(ceremony))
        .build()?)
}

/// Authentication leg 2: verify the assertion and deliver the primary token.
pub async fn handle_passkey_login_finish<S, B>(
    scheme: &S,
    ceremony_id: CeremonyId,
    response: serde_json::Value,
    builder: B,
) -> Result<B::Response, HandlerError<S::PasskeyError>>
where
    S: SupportsPasskeys + HttpAuthenticationScheme,
    B: ResponseBuilder,
{
    let outcome = scheme
        .finish_passkey_authentication(ceremony_id, response)
        .await
        .map_err(HandlerError::Auth)?;
    match outcome {
        // Reuse the scheme's normal login delivery (sets the auth cookie).
        LoginOutcome::Success(token) => {
            Ok(scheme.create_login_response(builder, LoginOutcome::Success(token))?)
        }
        // The scheme holds passkey logins to 2FA (`passkey_login_requires_2fa`).
        // `/verify-2fa` takes the email too, and a usernameless login never
        // asked for it, so it comes back here. Whoever holds the passkey may
        // know whose it is.
        LoginOutcome::Requires2Fa { email, attempt_id } => Ok(builder
            .status(206)
            .json_body(json!({
                "status": "requires_2fa",
                "message": "2FA required",
                "loginAttemptId": attempt_id.to_string(),
                "email": email.as_ref().expose_secret(),
            }))
            .build()?),
    }
}
