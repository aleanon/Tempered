use tempered_core::{HttpResponseBuilderExt, Password, ResponseBuilder, SupportsPasswordReset};

/// Completes a password reset using a reset token.
///
/// Returns 400 if the token is invalid or expired, or if the new password
/// fails validation.
pub async fn handle_complete_password_reset<S, B>(
    scheme: &S,
    reset_token: String,
    new_password: Password,
    builder: B,
) -> Result<B::Response, String>
where
    S: SupportsPasswordReset,
    B: ResponseBuilder,
{
    scheme
        .complete_password_reset(reset_token, new_password)
        .await
        .map_err(|e| e.to_string())?;

    builder
        .status(200)
        .json_body(serde_json::json!({
            "status": "success",
            "message": "Password reset successfully"
        }))
        .build()
        .map_err(|e| e.message)
}
