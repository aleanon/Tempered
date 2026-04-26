use tempered_core::{HttpResponseBuilderExt, ResponseBuilder, SupportsPasswordReset};

/// Initiates a password reset for the given email address.
///
/// Always returns 200 regardless of whether the email exists, to prevent
/// user enumeration attacks. Invalid email addresses are silently ignored.
pub async fn handle_initiate_password_reset<S, B>(
    scheme: &S,
    email: Option<tempered_core::Email>,
    builder: B,
) -> Result<B::Response, String>
where
    S: SupportsPasswordReset,
    B: ResponseBuilder,
{
    if let Some(email) = email {
        let _ = scheme.initiate_password_reset(email).await;
    }

    builder
        .status(200)
        .json_body(serde_json::json!({
            "status": "success",
            "message": "If that email address is registered, you will receive a password reset link"
        }))
        .build()
        .map_err(|e| e.message)
}
