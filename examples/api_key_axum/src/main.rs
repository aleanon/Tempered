//! Standalone Axum example crate: API key authentication, with a browser
//! frontend (see `assets/index.html`).
//!
//! ```bash
//! cargo run -p tempered-example-api-key
//! # open http://localhost:3000
//! ```
//!
//! The frontend lets you issue a key and call a protected route with it. The
//! protected route is guarded by `ApiKeyScheme`'s validator running as Axum
//! middleware (`tempered_axum::middleware::validate_token`), which inserts the
//! validated `ApiKeyClaims` into the request extensions.

use axum::{
    Extension, Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;
use tempered::{ApiKeyScheme, Email, ExposeSecret, HashMapApiKeyStore, Secret, SupportsApiKeyIssuance};
use tempered_adapters::authentication::api_key_scheme::ApiKeyClaims;
use tempered_axum::middleware::validate_token;
use tower_http::services::ServeDir;

type Scheme = ApiKeyScheme<HashMapApiKeyStore>;

const ASSETS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/assets");

#[tokio::main]
async fn main() {
    let scheme: Scheme = ApiKeyScheme::new(HashMapApiKeyStore::new());

    // Seed a key so the protected route is usable immediately.
    let owner = Email::try_from(Secret::new("demo@service.example".to_string())).unwrap();
    let (id, plaintext) = scheme
        .issue_api_key(owner, vec!["read".to_string()])
        .await
        .unwrap();
    println!("Seeded demo key (id={id}): {plaintext}");

    let protected = Router::new()
        .route("/protected", get(protected))
        .layer(axum::middleware::from_fn_with_state(
            scheme.clone(),
            validate_token::<Scheme>,
        ));

    let app = Router::new()
        .route("/api-keys", post(issue_key))
        .merge(protected)
        .with_state(scheme)
        .fallback_service(ServeDir::new(ASSETS));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("listening on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

#[derive(Deserialize)]
struct IssueRequest {
    email: String,
    #[serde(default)]
    scopes: Vec<String>,
}

/// Issue a new key for an owner; the plaintext is returned exactly once.
async fn issue_key(
    State(scheme): State<Scheme>,
    Json(req): Json<IssueRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let owner = Email::try_from(Secret::new(req.email))
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let (id, plaintext) = scheme
        .issue_api_key(owner, req.scopes)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "id": id.to_string(), "api_key": plaintext })))
}

/// Reachable only with a valid key; echoes the validated claims.
async fn protected(Extension(claims): Extension<ApiKeyClaims>) -> Json<serde_json::Value> {
    Json(json!({
        "message": "authenticated via API key",
        "key_id": claims.id.to_string(),
        "owner": claims.owner.as_ref().expose_secret(),
        "scopes": claims.scopes,
    }))
}
