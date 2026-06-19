//! Axum example: API key authentication.
//!
//! ```bash
//! cargo run --example api_key_axum
//! ```
//!
//! On startup it prints a demo key. Use it on the protected route:
//! ```bash
//! curl -H 'x-api-key: <KEY>' http://localhost:3000/protected
//! ```
//! Issue another key:
//! ```bash
//! curl -X POST http://localhost:3000/api-keys \
//!   -H 'content-type: application/json' \
//!   -d '{"email":"svc@example.com","scopes":["read","write"]}'
//! ```
//!
//! The key is validated by `ApiKeyScheme`'s validator running as Axum
//! middleware (`tempered_axum::middleware::validate_token`), which inserts the
//! `ApiKeyClaims` into the request extensions for the handler to read.

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

type Scheme = ApiKeyScheme<HashMapApiKeyStore>;

#[tokio::main]
async fn main() {
    let scheme: Scheme = ApiKeyScheme::new(HashMapApiKeyStore::new());

    // Seed a key so you can call the protected route right away.
    let owner = Email::try_from(Secret::new("demo@service.example".to_string())).unwrap();
    let (id, plaintext) = scheme
        .issue_api_key(owner, vec!["read".to_string()])
        .await
        .unwrap();
    println!("──────────────────────────────────────────────────────────");
    println!("Demo API key (id={id}):\n  {plaintext}");
    println!("Try: curl -H 'x-api-key: {plaintext}' http://localhost:3000/protected");
    println!("──────────────────────────────────────────────────────────");

    // Routes behind the API key validator. The middleware returns 401 if the
    // key is missing/invalid, otherwise inserts ApiKeyClaims into extensions.
    let protected = Router::new()
        .route("/protected", get(protected))
        .layer(axum::middleware::from_fn_with_state(
            scheme.clone(),
            validate_token::<Scheme>,
        ));

    let app = Router::new()
        .route("/", get(index))
        .route("/api-keys", post(issue_key))
        .merge(protected)
        .with_state(scheme);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("listening on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> &'static str {
    "API key example. POST /api-keys to issue a key; GET /protected with header 'x-api-key: <key>'."
}

#[derive(Deserialize)]
struct IssueRequest {
    email: String,
    #[serde(default)]
    scopes: Vec<String>,
}

/// Issue a new key for an owner. The plaintext is returned exactly once.
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
