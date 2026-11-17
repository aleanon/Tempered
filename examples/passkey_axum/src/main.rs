//! Standalone Axum example crate: passkey (WebAuthn) login folded into
//! `JwtScheme` as a capability, with a browser frontend (see `assets/index.html`).
//!
//! ```bash
//! cargo run -p tempered-example-passkey
//! # open http://localhost:3000
//! ```
//!
//! Like the OAuth example, this is **fully self-contained and offline**: it ships
//! a deliberately trivial [`DemoVerifier`] that stands in for a real
//! `webauthn-rs`-backed [`WebAuthnVerifier`], and the frontend *simulates* the
//! authenticator instead of calling `navigator.credentials`. That keeps the demo
//! deterministic while exercising the real server-side capability:
//! `JwtScheme::new(...).supports_passkeys(flow)`. The passkey ceremony routes
//! **auto-wire** from that `supports_passkeys` call — there is no route opt-in to
//! add (pass a path to `auth_service(...).passkeys(..)` only to override the
//! prefix).
//!
//! Passkeys are enrolled **for an existing, logged-in account**: the two
//! `register/*` routes sit behind the login middleware and enroll for the
//! session's owner, so the demo first creates an account with a password, logs
//! in, enrolls a passkey, logs out, and then signs back in with the passkey
//! alone. (Enrolling must be authenticated — otherwise anyone could attach their
//! own authenticator to someone else's account.)
//!
//! A successful authentication ceremony issues the scheme's **primary JWT** — the
//! same session cookie a password or OAuth login would produce, which `/me`
//! validates below.
//!
//! Note: like the OAuth example, `/me` validates the JWT manually to prove the
//! session is real, which is why this example names the fully applied `Scheme`
//! type. A normal protected route needs none of that — use
//! `auth_service(...).validated_router(...)` with `Extension<Claims>` (see the
//! `jwt_standalone` example).
//!
//! ⚠️  `DemoVerifier` performs no cryptography and trusts the client-supplied
//! credential id. A production deployment plugs a real `WebAuthnVerifier` (e.g.
//! `webauthn-rs`) into the exact same `PasskeyFlow` and uses real
//! `navigator.credentials` in the browser — no server wiring changes.

use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::json;
use tempered::core::{
    AuthValidator, AuthenticationScheme, CeremonyStart, CeremonyState, CredentialId,
    PasskeyCredential, VerifiedAssertion, VerifiedRegistration, WebAuthnError, WebAuthnVerifier,
};
use tempered::{
    ExposeSecret, HashMapChallengeStore, HashMapPasskeyCredentialStore, HashMapTokenEpochStore,
    HashMapUserStore, HashSetBannedTokenStore, JwtAuthConfig, JwtScheme, PasskeyFlow, Passkeys,
    Secret, auth_service,
};

/// The fully-applied scheme type: a JWT core with only the passkey slot enabled
/// (password signup is a runtime flag, not a type-level slot).
type Scheme = JwtScheme<
    HashMapUserStore,
    HashSetBannedTokenStore,
    (),
    (),
    (),
    (),
    (),
    Passkeys<HashMapPasskeyCredentialStore, HashMapChallengeStore, DemoVerifier>,
>;

const BASE: &str = "http://localhost:3000";
const ASSETS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/assets");

#[tokio::main]
async fn main() {
    let flow = PasskeyFlow::new(
        HashMapPasskeyCredentialStore::new(),
        HashMapChallengeStore::new(),
        DemoVerifier,
    );

    let jwt_config = JwtAuthConfig {
        jwt_cookie_name: "jwt".to_string(),
        jwt_secret: Secret::new("input a long random generated string here".to_string()),
        token_ttl_in_seconds: 3600,
        audience: None,
        issuer: None,
    };

    // Password signup creates the account a passkey is then enrolled for.
    let scheme: Scheme = JwtScheme::new(
        HashMapUserStore::new(),
        jwt_config,
        HashSetBannedTokenStore::new(),
        HashMapTokenEpochStore::new(),
    )
    .supports_registration()
    .supports_passkeys(flow);

    // The four passkey ceremony routes under `/passkey/*` auto-wire from
    // `supports_passkeys`: `register/{start,finish}` behind the login middleware,
    // `login/{start,finish}` public. `/signup`, `/login`, `/logout` and the
    // frontend come for free.
    let auth_router: Router = auth_service(scheme.clone(), ASSETS.to_string()).into();

    // `/me` reads the JWT the login ceremony issued, so it needs the scheme as
    // state and lives in a sibling router merged into the auth service.
    let extra: Router = Router::new().route("/me", get(me)).with_state(scheme);

    let app = auth_router.merge(extra);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("listening on {BASE}");
    axum::serve(listener, app).await.unwrap();
}

/// Report the currently logged-in user by validating the JWT the passkey login
/// issued — proving a passkey login yields a normal, verifiable session.
async fn me(State(scheme): State<Scheme>, headers: HeaderMap) -> Response {
    let (mut parts, _) = axum::http::Request::new(()).into_parts();
    parts.headers = headers;

    match scheme.validator().validate(&parts).await {
        Ok(claims) => Json(json!({ "email": claims.sub.expose_secret() })).into_response(),
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "not logged in" })),
        )
            .into_response(),
    }
}

// ---- Demo verifier (stand-in for a real `webauthn-rs` adapter) -------------
//
// It performs NO cryptography: registration trusts the client-supplied
// credential id, and authentication trusts the asserted sign count. This is only
// safe because the example simulates the authenticator; never ship this.
//
// What it does show is the shape of the port: the verifier issues the challenge
// itself, hands back opaque state for the library to keep server-side between
// the two legs, and gets that state back to finish the ceremony.

#[derive(Clone)]
struct DemoVerifier;

static NEXT_CHALLENGE: AtomicU64 = AtomicU64::new(1);

impl DemoVerifier {
    /// A real verifier returns full `PublicKeyCredentialCreationOptions` /
    /// `…RequestOptions` and serialized ceremony state; the simulated frontend
    /// only needs a challenge to echo back.
    fn start(&self) -> CeremonyStart {
        let challenge = format!(
            "demo-challenge-{}",
            NEXT_CHALLENGE.fetch_add(1, Ordering::Relaxed)
        );
        CeremonyStart {
            options: json!({ "challenge": challenge, "rp": { "id": "localhost" } }),
            state: CeremonyState(challenge.into_bytes()),
        }
    }

    /// The one check the demo does make: the response answers *this* ceremony.
    fn check_challenge(
        state: &CeremonyState,
        response: &serde_json::Value,
    ) -> Result<(), WebAuthnError> {
        let echoed = response.get("challenge").and_then(|v| v.as_str());
        if echoed.map(str::as_bytes) == Some(state.0.as_slice()) {
            Ok(())
        } else {
            Err(WebAuthnError::Verification("challenge mismatch".into()))
        }
    }
}

impl WebAuthnVerifier for DemoVerifier {
    fn start_registration(
        &self,
        _email: &tempered::Email,
        _existing: &[PasskeyCredential],
    ) -> Result<CeremonyStart, WebAuthnError> {
        Ok(self.start())
    }

    fn finish_registration(
        &self,
        state: &CeremonyState,
        response: &serde_json::Value,
    ) -> Result<VerifiedRegistration, WebAuthnError> {
        Self::check_challenge(state, response)?;
        let id = credential_id(response)?;
        Ok(VerifiedRegistration {
            credential_id: CredentialId(id),
            // A real verifier stores the public key (or its whole credential).
            credential_data: vec![0xde, 0xad, 0xbe, 0xef],
            sign_count: 0,
        })
    }

    fn start_authentication(
        &self,
        _allowed: &[PasskeyCredential],
    ) -> Result<CeremonyStart, WebAuthnError> {
        Ok(self.start())
    }

    fn finish_authentication(
        &self,
        state: &CeremonyState,
        response: &serde_json::Value,
        stored: &PasskeyCredential,
    ) -> Result<VerifiedAssertion, WebAuthnError> {
        Self::check_challenge(state, response)?;
        // Trust the asserted counter; the flow still enforces monotonicity.
        let new_sign_count = response
            .get("sign_count")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32)
            .unwrap_or(stored.sign_count + 1);
        Ok(VerifiedAssertion {
            credential_id: stored.credential_id.clone(),
            new_sign_count,
            updated_credential_data: None,
        })
    }
}

fn credential_id(response: &serde_json::Value) -> Result<String, WebAuthnError> {
    response
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| WebAuthnError::Malformed("missing credential id".into()))
}
