use tempered_core::{HttpResponseBuilderExt, RequiresEmailVerification, ResponseBuilder};

use crate::handlers::HandlerError;

pub async fn handle_verify_email<S, B>(
    scheme: &S,
    token: String,
    builder: B,
) -> Result<B::Response, HandlerError<S::EmailVerificationError>>
where
    S: RequiresEmailVerification,
    B: ResponseBuilder,
{
    scheme
        .verify_email(token)
        .await
        .map_err(HandlerError::Auth)?;

    Ok(builder
        .status(200)
        .json_body(serde_json::json!({
            "status": "success",
            "message": "Email verified successfully"
        }))
        .build()?)
}
