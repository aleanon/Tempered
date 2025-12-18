use tempered_adapters::http::error::{AuthApiError, ErrorResponse};

use crate::helpers::{TestApp, get_standard_test_user};

#[tokio::test]
pub async fn should_return_204_with_valid_elevated_auth_token() {
    let client = TestApp::new().await;

    let body = get_standard_test_user(false);

    let user_created = client.post_signup(&body).await;
    assert_eq!(user_created.status().as_u16(), 201);

    assert_eq!(client.login(&body).await.status().as_u16(), 200);

    assert_eq!(client.post_elevate(&body).await.status().as_u16(), 200);

    let user_deleted = client.delete_account().await;
    let status_code = user_deleted.status().as_u16();
    let error_message = user_deleted
        .json::<ErrorResponse>()
        .await
        .unwrap_or(ErrorResponse {
            error: "".to_owned(),
        })
        .error;
    println!("{error_message}");
    assert_eq!(status_code, 204);
}

#[tokio::test]
pub async fn should_return_400_without_elevated_auth_token() {
    let app = TestApp::new().await;

    let body = get_standard_test_user(false);
    assert_eq!(app.post_signup(&body).await.status().as_u16(), 201);

    assert_eq!(app.login(&body).await.status().as_u16(), 200);

    let user_deleted = app.delete_account().await;
    assert_eq!(user_deleted.status().as_u16(), 400);
    assert_eq!(
        user_deleted
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        AuthApiError::MissingToken.to_string()
    );
}

#[tokio::test]
pub async fn should_return_400_after_logout() {
    let client = TestApp::new().await;
    let body = get_standard_test_user(false);

    client.post_signup(&body).await;
    client.login(&body).await;
    client.post_elevate(&body).await;
    client.logout().await;

    let response = client.delete_account().await;
    assert_eq!(response.status().as_u16(), 400);
    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        AuthApiError::MissingToken.to_string()
    );
}
