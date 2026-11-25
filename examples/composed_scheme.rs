//! Composing two authentication schemes, the library's way.
//!
//! `auth_service` serves exactly one scheme, and the library ships no
//! composite: you compose on your own type and decide the rules yourself.
//! This example lets people log in with a password (a JWT cookie) and lets
//! services call the same endpoints with an API key:
//!
//! - `AppScheme` holds both schemes. Logging in and out is the JWT
//!   scheme's job, so those delegate to it.
//! - `CallerValidator` is the "try in order" logic: a request that carries
//!   an API key is judged by the key alone, anything else by the JWT
//!   cookie. Its claims are a `Caller` enum, which handlers read with
//!   `Extension<Caller>`.
//! - The JWT scheme's own routes (`/signup`, `/login`, ...) come from
//!   `auth_service` as usual. The shared routes go behind the library's
//!   `validate_token` middleware, instantiated for `AppScheme`.
//!
//! ```bash
//! cargo run --example composed_scheme
//! curl -i -X POST localhost:3000/signup -H 'content-type: application/json' \
//!   -d '{"email":"a@example.com","password":"correct-horse","requires2FA":false}'
//! curl -i -X POST localhost:3000/login -c jar -H 'content-type: application/json' \
//!   -d '{"email":"a@example.com","password":"correct-horse"}'
//! curl -b jar localhost:3000/whoami                      # a person, by cookie
//! curl -H "x-api-key: <printed key>" localhost:3000/whoami  # a service, by key
//! ```
//!
//! The cookie is `Secure`, so curl only sends it back over HTTPS or to
//! `localhost`.

use axum::{Extension, Router, routing::get};
use tempered::core::{AuthValidator, AuthenticationScheme, LoginOutcome};
use tempered::{
    ApiKeyClaims, ApiKeyScheme, Claims, ClassifyError, ErrorCategory, ExposeSecret,
    HashMapApiKeyStore, HashMapTokenEpochStore, HashMapUserStore, HashSetBannedTokenStore,
    Issuance, JwtAuthConfig, JwtScheme, Secret, SupportsApiKeyIssuance, async_trait, auth_service,
    validate_token,
};

/// People: password login, JWT cookie.
type People = JwtScheme<HashMapUserStore, HashSetBannedTokenStore>;
/// Services: API keys in `x-api-key` (or `Authorization: Bearer`).
type Services = ApiKeyScheme<HashMapApiKeyStore, Issuance>;

type PeopleValidator = <People as AuthenticationScheme>::Validator;
type ServicesValidator = <Services as AuthenticationScheme>::Validator;

/// Who called: the claims of whichever method accepted the request.
#[derive(Clone, Debug)]
pub enum Caller {
    Person(Claims),
    Service(ApiKeyClaims),
}

/// Why neither method accepted the request: the chosen method's own error.
#[derive(Debug, thiserror::Error)]
pub enum CallerError {
    #[error(transparent)]
    Person(<PeopleValidator as AuthValidator>::Error),
    #[error(transparent)]
    Service(<ServicesValidator as AuthValidator>::Error),
}

impl ClassifyError for CallerError {
    fn classify(self) -> (ErrorCategory, String) {
        match self {
            CallerError::Person(e) => e.classify(),
            CallerError::Service(e) => e.classify(),
        }
    }
}

/// The "try in order" rule, in one place you own.
#[derive(Clone)]
pub struct CallerValidator {
    people: PeopleValidator,
    services: ServicesValidator,
}

/// A request presents an API key if it has either header the key validator
/// reads.
fn presents_api_key(parts: &http::request::Parts) -> bool {
    parts.headers.contains_key("x-api-key")
        || parts
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("Bearer "))
}

#[async_trait]
impl AuthValidator for CallerValidator {
    type Claims = Caller;
    type RequestParts = http::request::Parts;
    type Error = CallerError;

    async fn validate(&self, parts: &Self::RequestParts) -> Result<Caller, CallerError> {
        // A request that presents a key is judged by the key alone: a bad
        // key is refused even if a valid cookie rides along, so a service
        // never runs as whoever's browser it happens to be in.
        if presents_api_key(parts) {
            return self
                .services
                .validate(parts)
                .await
                .map(Caller::Service)
                .map_err(CallerError::Service);
        }
        self.people
            .validate(parts)
            .await
            .map(Caller::Person)
            .map_err(CallerError::Person)
    }
}

/// The app's scheme: both methods, one validator.
#[derive(Clone)]
pub struct AppScheme {
    people: People,
    services: Services,
    validator: CallerValidator,
}

impl AppScheme {
    pub fn new(people: People, services: Services) -> Self {
        let validator = CallerValidator {
            people: people.validator().clone(),
            services: services.validator().clone(),
        };
        Self {
            people,
            services,
            validator,
        }
    }

    /// The key scheme, for issuing keys (an admin route would call this).
    pub fn services(&self) -> &Services {
        &self.services
    }
}

#[async_trait]
impl AuthenticationScheme for AppScheme {
    // Only people log in; services present a key on every request.
    type Token = <People as AuthenticationScheme>::Token;
    type LogoutOutput = <People as AuthenticationScheme>::LogoutOutput;
    type Validator = CallerValidator;
    type Credentials = <People as AuthenticationScheme>::Credentials;
    type AuthError = <People as AuthenticationScheme>::AuthError;

    async fn login(
        &self,
        credentials: Self::Credentials,
    ) -> Result<LoginOutcome<Self::Token>, Self::AuthError> {
        self.people.login(credentials).await
    }

    async fn logout(&self, token: &Self::Token) -> Result<Self::LogoutOutput, Self::AuthError> {
        self.people.logout(token).await
    }

    fn validator(&self) -> &CallerValidator {
        &self.validator
    }
}

/// The whole app: the JWT scheme's routes plus `/whoami` for either caller.
fn app(scheme: AppScheme) -> Router {
    let shared =
        Router::new()
            .route("/whoami", get(whoami))
            .layer(axum::middleware::from_fn_with_state(
                scheme.clone(),
                validate_token::<AppScheme>,
            ));
    let people: Router = auth_service(scheme.people, String::new()).into();
    shared.merge(people)
}

async fn whoami(Extension(caller): Extension<Caller>) -> String {
    match caller {
        Caller::Person(claims) => format!("person {}", claims.sub.expose_secret()),
        Caller::Service(key) => format!("service {} (key {})", key.owner, key.id),
    }
}

fn people() -> People {
    JwtScheme::new(
        HashMapUserStore::new(),
        JwtAuthConfig {
            jwt_cookie_name: "__Host-jwt".to_string(),
            // Load this from the environment in real code.
            jwt_secret: Secret::new("an example secret that is at least 32 bytes".to_string()),
            token_ttl_in_seconds: 3600,
            audience: None,
            issuer: None,
        },
        HashSetBannedTokenStore::new(),
        HashMapTokenEpochStore::new(),
    )
    .supports_registration()
}

fn services() -> Services {
    ApiKeyScheme::new(HashMapApiKeyStore::new()).supports_issuance()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scheme = AppScheme::new(people(), services());
    // The billing service's id (keys belong to an id, not an address).
    let owner = tempered::core::UserId::new();
    let (_, key) = scheme.services().issue_api_key(owner, vec![]).await?;
    println!("service key: {key}");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    println!("listening on http://localhost:3000");
    axum::serve(listener, app(scheme)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn call(app: &Router, request: Request<Body>) -> (StatusCode, String) {
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 1 << 16).await.unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    fn json(method: &str, uri: &str, body: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn whoami(header: (&str, &str)) -> Request<Body> {
        Request::builder()
            .uri("/whoami")
            .header(header.0, header.1)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn a_person_and_a_service_reach_the_same_route() {
        let services = services();
        let owner = tempered::core::UserId::new();
        let (_, key) = services.issue_api_key(owner, vec![]).await.unwrap();
        // (`owner` is checked against the reply below.)
        let app = app(AppScheme::new(people(), services));

        let creds = r#"{"email":"a@example.com","password":"correct-horse","requires2FA":false}"#;
        assert!(
            call(&app, json("POST", "/signup", creds))
                .await
                .0
                .is_success()
        );
        let response = app
            .clone()
            .oneshot(json("POST", "/login", creds))
            .await
            .unwrap();
        assert!(response.status().is_success());
        let cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();

        // A person, by cookie.
        let (status, body) = call(&app, whoami(("cookie", &cookie))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "person a@example.com");

        // A service, by key.
        let (status, body) = call(&app, whoami(("x-api-key", &key))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.starts_with(&format!("service {owner}")), "{body}");

        // Neither.
        let (status, _) = call(&app, Request::get("/whoami").body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_bad_key_is_refused_even_with_a_good_cookie() {
        let app = app(AppScheme::new(people(), services()));
        let creds = r#"{"email":"a@example.com","password":"correct-horse","requires2FA":false}"#;
        call(&app, json("POST", "/signup", creds)).await;
        let response = app
            .clone()
            .oneshot(json("POST", "/login", creds))
            .await
            .unwrap();
        let cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();

        let request = Request::builder()
            .uri("/whoami")
            .header("cookie", cookie)
            .header("x-api-key", "not-a-key")
            .body(Body::empty())
            .unwrap();
        // Refused (a malformed key is a 400, an unknown one a 401), not
        // let through as the cookie's person.
        let (status, body) = call(&app, request).await;
        assert!(status.is_client_error(), "{status}");
        assert!(!body.contains("person"), "{body}");
    }
}
