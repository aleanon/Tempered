//! OpenID Connect ID token verification (OIDC Core §3.1.3.7).
//!
//! The token's signature is checked with the provider's published keys
//! (JWKS, cached), then its issuer, audience, authorized party, expiry and
//! nonce. Only asymmetric algorithms are accepted: a token "signed" with
//! `none`, or with HMAC under a public key, is refused.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{Jwk, JwkSet},
};
use serde::Deserialize;
use tempered_core::{OAuthHttpClient, OidcSettings, constant_time_eq};

/// How long a fetched key set is used before it is fetched again.
const KEYS_FRESH_FOR: Duration = Duration::from_secs(60 * 60);
/// A token with an unknown key id refetches the set, at most this often
/// (providers rotate keys; an attacker should not be able to make every
/// callback fetch).
const REFETCH_AT_MOST_EVERY: Duration = Duration::from_secs(60);
/// Clock skew allowed on `exp` and `iat`.
const LEEWAY_SECONDS: u64 = 60;

const ALLOWED: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

/// The claims of a verified ID token that the login uses.
#[derive(Debug, Clone)]
pub(crate) struct IdClaims {
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
}

#[derive(Deserialize)]
struct RawClaims {
    sub: String,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    azp: Option<String>,
    aud: Audience,
    #[serde(default)]
    email: Option<String>,
    /// A boolean, or `"true"` / `"false"` from some providers.
    #[serde(default)]
    email_verified: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    // `Many` first: untagged tries variants in order, and `IgnoredAny`
    // accepts anything, arrays included.
    Many(Vec<String>),
    /// One audience; `jsonwebtoken` has already checked it is ours.
    One(serde::de::IgnoredAny),
}

/// Key sets per JWKS URI, shared by every login.
#[derive(Default)]
pub(crate) struct KeyCache {
    sets: Mutex<HashMap<String, (JwkSet, Instant)>>,
}

impl KeyCache {
    /// Verify `token` as an ID token from `oidc`'s issuer for `client_id`,
    /// answering the login that sent `nonce`.
    pub(crate) async fn verify<HC: OAuthHttpClient>(
        &self,
        http: &HC,
        oidc: &OidcSettings,
        client_id: &str,
        token: &str,
        nonce: &str,
    ) -> Result<IdClaims, String> {
        let header = decode_header(token).map_err(|e| format!("unreadable header: {e}"))?;
        if !ALLOWED.contains(&header.alg) {
            return Err(format!("algorithm {:?} is not accepted", header.alg));
        }
        let jwk = self.key(http, oidc, header.kid.as_deref()).await?;
        let key = DecodingKey::from_jwk(&jwk).map_err(|e| format!("unusable key: {e}"))?;

        let mut validation = Validation::new(header.alg);
        validation.leeway = LEEWAY_SECONDS;
        validation.set_issuer(&[&oidc.issuer]);
        validation.set_audience(&[client_id]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        let claims: RawClaims = decode(token, &key, &validation)
            .map_err(|e| format!("refused: {e}"))?
            .claims;

        // The nonce ties the token to this login (no replay of a token
        // obtained for another).
        let echoed = claims.nonce.as_deref().unwrap_or("");
        if !constant_time_eq(echoed, nonce) {
            return Err("nonce does not match this login".to_string());
        }
        // With several audiences, the token must say it was issued to us.
        let several = matches!(&claims.aud, Audience::Many(a) if a.len() > 1);
        match claims.azp.as_deref() {
            Some(azp) if azp != client_id => return Err("issued to another client".to_string()),
            None if several => return Err("several audiences and no azp".to_string()),
            _ => {}
        }
        let email_verified = match claims.email_verified {
            Some(serde_json::Value::Bool(b)) => b,
            Some(serde_json::Value::String(s)) => s == "true",
            _ => false,
        };
        Ok(IdClaims {
            subject: claims.sub,
            email: claims.email,
            email_verified,
        })
    }

    /// The key `kid` names (or the only key, when the token names none),
    /// fetching the set when it is stale or does not have it.
    async fn key<HC: OAuthHttpClient>(
        &self,
        http: &HC,
        oidc: &OidcSettings,
        kid: Option<&str>,
    ) -> Result<Jwk, String> {
        let cached = {
            let sets = self.sets.lock().expect("key cache poisoned");
            sets.get(&oidc.jwks_uri).cloned()
        };
        if let Some((set, fetched)) = &cached {
            let fresh = fetched.elapsed() < KEYS_FRESH_FOR;
            if let Some(jwk) = pick(set, kid)
                && fresh
            {
                return Ok(jwk);
            }
            if fresh && fetched.elapsed() < REFETCH_AT_MOST_EVERY {
                return Err("no matching key (key set fetched just now)".to_string());
            }
        }
        let json = http
            .fetch_json(&oidc.jwks_uri)
            .await
            .map_err(|e| format!("key set: {e}"))?;
        let set: JwkSet = serde_json::from_value(json).map_err(|e| format!("key set: {e}"))?;
        let jwk = pick(&set, kid);
        self.sets
            .lock()
            .expect("key cache poisoned")
            .insert(oidc.jwks_uri.clone(), (set, Instant::now()));
        jwk.ok_or_else(|| "no matching key".to_string())
    }
}

fn pick(set: &JwkSet, kid: Option<&str>) -> Option<Jwk> {
    match kid {
        Some(kid) => set.find(kid).cloned(),
        None if set.keys.len() == 1 => set.keys.first().cloned(),
        None => None,
    }
}
