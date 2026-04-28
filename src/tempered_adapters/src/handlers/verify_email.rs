use tempered_core::{HttpResponseBuilderExt, RequiresEmailVerification, ResponseBuilder};

pub async fn handle_verify_email<S, B>(
    scheme: &S,
    token: String,
    builder: B,
) -> Result<B::Response, S::EmailVerificationError>
where
    S: RequiresEmailVerification,
    B: ResponseBuilder,
{
    scheme.verify_email(token).await?;

    builder
        .status(200)
        .json_body(serde_json::json!({
            "status": "success",
            "message": "Email verified successfully"
        }))
        .build()
        .map_err(|_| panic!("ResponseBuilder error in verify_email handler - this is a bug"))
}
