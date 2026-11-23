//! The static-file fallback serves the assets directory, but never its
//! hidden files: an `assets_dir` of `"."` must not hand out `.env`.

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use secrecy::Secret;
use tempered_adapters::auth_validation::local_jwt_validator::JwtAuthConfig;
use tempered_adapters::authentication::jwt_scheme::JwtScheme;
use tempered_adapters::persistence::{
    HashMapTokenEpochStore, HashMapUserStore, HashSetBannedTokenStore,
};
use tempered_axum::auth_service::auth_service;
use tower::ServiceExt; // for `oneshot`

const SECRET: &str = "JWT_SECRET=do-not-serve-me";

/// An assets directory with a page, a `.env`, a `.git/` and a `.well-known/`.
fn assets_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("tempered-assets-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join(".well-known")).unwrap();
    std::fs::write(dir.join("index.html"), "<h1>app</h1>").unwrap();
    std::fs::write(dir.join("app.js"), "console.log(1)").unwrap();
    std::fs::write(dir.join(".env"), SECRET).unwrap();
    std::fs::write(dir.join(".git/config"), SECRET).unwrap();
    std::fs::write(dir.join(".well-known/security.txt"), "Contact: x").unwrap();
    dir
}

fn app(dir: &std::path::Path) -> Router {
    let scheme = JwtScheme::new(
        HashMapUserStore::new(),
        JwtAuthConfig {
            jwt_cookie_name: "jwt".to_string(),
            jwt_secret: Secret::new("a-test-secret-that-is-long-enough".to_string()),
            token_ttl_in_seconds: 3600,
            audience: None,
            issuer: None,
        },
        HashSetBannedTokenStore::new(),
        HashMapTokenEpochStore::new(),
    );
    auth_service(scheme, dir.to_str().unwrap().to_string()).into()
}

async fn get(app: &Router, path: &str) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn hidden_files_are_not_served() {
    let dir = assets_dir();
    let app = app(&dir);
    for path in ["/.env", "/%2Eenv", "/.git/config", "/x/..%2F.env"] {
        let (status, body) = get(&app, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert!(!body.contains("do-not-serve-me"), "{path} leaked: {body}");
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn public_files_and_well_known_are_served() {
    let dir = assets_dir();
    let app = app(&dir);
    assert_eq!(
        get(&app, "/app.js").await,
        (StatusCode::OK, "console.log(1)".to_string())
    );
    assert_eq!(get(&app, "/").await.0, StatusCode::OK);
    let (status, body) = get(&app, "/.well-known/security.txt").await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "Contact: x"));
    std::fs::remove_dir_all(dir).unwrap();
}
